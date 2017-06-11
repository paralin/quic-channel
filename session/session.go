package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
)

// handshakeTimeout is the time allowed for a handshake.
var handshakeTimeout = time.Duration(3 * time.Second)

// keepAliveFrequency is how often we send a keep alive packet.
var keepAliveFrequency = time.Duration(1) * time.Second

// inactivityTimeout is the time allowed for inactivity after the handshake
var inactivityTimeout = time.Duration(5) * time.Second

// Session manages a connection with a remote peer.
type Session struct {
	context           context.Context
	log               *log.Entry
	initiator         bool
	started           time.Time
	manager           SessionManager
	session           quic.Session
	pumpErrors        chan error
	inactivityTimer   *time.Timer
	inactivityTimeout time.Duration

	childContext       context.Context
	childContextCancel context.CancelFunc

	streamHandlersMtx sync.Mutex
	streamHandlers    map[protocol.StreamID]StreamHandler

	sessionDataMtx sync.Mutex
	sessionData    map[uint32]interface{}
}

// SessionReadyDetails contains information about the session becoming ready.
type SessionReadyDetails struct {
	// InitiatedTimestamp is when this session was initiated.
	InitiatedTimestamp time.Time
}

// SessionManager manages a session.
type SessionManager interface {
	// OnSessionReady is called when the session is finished initializing.
	// Returning an error will terminate the session with the error.
	OnSessionReady(details *SessionReadyDetails) error
	// OnSessionClosed is called when a session is closed.
	OnSessionClosed(sess *Session, err error)
}

// SessionConfig contains arguments to build a session.
type SessionConfig struct {
	// Manager is the session manager.
	Manager SessionManager
	// Context, when cancelled will close the session.
	Context context.Context
	// Session to wrap.
	Session quic.Session
	// Initiator if we are the initiator of the session.
	Initiator bool
}

// NewSession builds a new session.
func NewSession(config SessionConfig) (*Session, error) {
	s := &Session{
		context:           config.Context,
		session:           config.Session,
		initiator:         config.Initiator,
		log:               log.WithField("remote", config.Session.RemoteAddr().String()),
		pumpErrors:        make(chan error, 2),
		streamHandlers:    make(map[protocol.StreamID]StreamHandler),
		started:           time.Now(),
		inactivityTimeout: handshakeTimeout,
		inactivityTimer:   time.NewTimer(handshakeTimeout),
		sessionData:       make(map[uint32]interface{}),
		manager:           config.Manager,
	}
	s.childContext, s.childContextCancel = context.WithCancel(config.Context)
	if config.Initiator {
		handler, err := s.OpenStream(EStreamType_STREAM_CONTROL)
		if err != nil {
			return nil, err
		}
		ch := handler.(*controlStreamHandler)
		if err := ch.SendSessionInit(s.started); err != nil {
			return nil, err
		}
	}
	s.startPump(s.acceptStreamPump)
	go s.manageCloseConditions()
	return s, nil
}

// handleIncomingStream handles an incoming quic stream.
func (s *Session) handleIncomingStream(stream quic.Stream) error {
	l := s.log.WithField("stream", int(stream.StreamID()))

	l.Debug("Stream opened")
	rw := packet.NewPacketReadWriter(stream)
	si := &StreamInit{}
	_, err := rw.ReadPacket(func(packetType uint32) (packet.Packet, error) {
		if packetType != 1 {
			return nil, fmt.Errorf("Expected packet type 1, got %d", packetType)
		}
		return si, nil
	})
	if err != nil {
		return err
	}

	handlerBuilder, ok := StreamHandlerBuilders[si.StreamType]
	if !ok {
		return fmt.Errorf("Unknown stream type: %s", si.StreamType.String())
	}

	handler, err := handlerBuilder.BuildHandler(&StreamHandlerConfig{
		Initiator: false,
		Log:       l,
		Session:   s,
		PacketRw:  rw,
		Stream:    stream,
	})
	if err != nil {
		return err
	}

	l.WithField("streamType", si.StreamType.String()).Debug("Stream initialized")
	go s.runStreamHandler(stream.StreamID(), handler)

	return nil
}

// runStreamHandler manages a stream handler.
func (s *Session) runStreamHandler(id protocol.StreamID, handler StreamHandler) {
	s.streamHandlersMtx.Lock()
	s.streamHandlers[id] = handler
	s.streamHandlersMtx.Unlock()

	ctx, ctxCancel := context.WithCancel(s.childContext)
	defer ctxCancel()

	err := handler.Handle(ctx)
	l := log.WithField("stream", uint32(id))
	if err != nil {
		l.WithError(err).Warn("Stream closed with error")
	} else {
		l.Debug("Stream closed")
	}

	s.streamHandlersMtx.Lock()
	delete(s.streamHandlers, id)
	s.streamHandlersMtx.Unlock()
}

// startPump starts a goroutine that will end the session if returned.
func (s *Session) startPump(pump func() error) {
	go func() {
		select {
		case s.pumpErrors <- pump():
		default:
		}
	}()
}

// acceptStreamPump handles incoming streams.
func (s *Session) acceptStreamPump() error {
	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			return err
		}

		if err := s.handleIncomingStream(stream); err != nil {
			return err
		}
	}
}

// manageCloseConditions returns when the session closes.
func (s *Session) manageCloseConditions() (sessErr error) {
	defer func() {
		l := s.log
		if sessErr != nil {
			l = l.WithError(sessErr)
		}
		if s.session != nil {
			s.session.Close(sessErr)
		}
		if s.manager != nil {
			s.manager.OnSessionClosed(s, sessErr)
		}
		if s.childContextCancel != nil {
			s.childContextCancel()
		}
		l.Debug("Session closed")
	}()

	s.log.Debug("Session started")
	select {
	case <-s.context.Done():
		return context.Canceled
	case <-s.inactivityTimer.C:
		return errors.New("Inactivity timeout reached.")
	case err := <-s.pumpErrors:
		return err
	}
}

// GetOrPutData gets the existing session data by ID or creates it.
func (s *Session) GetOrPutData(id uint32, builder func() interface{}) interface{} {
	s.sessionDataMtx.Lock()
	defer s.sessionDataMtx.Unlock()

	data, ok := s.sessionData[id]
	if !ok {
		data = builder()
		s.sessionData[id] = data
	}
	return data
}

// ResetInactivityTimeout resets the timeout.
// If zero is passed, maintains last duration.
func (s *Session) ResetInactivityTimeout(dur time.Duration) {
	if dur == 0 {
		dur = s.inactivityTimeout
	} else {
		s.inactivityTimeout = dur
	}

	s.inactivityTimer.Reset(dur)
}

// DeleteData removes data from the session data store.
func (s *Session) DeleteData(id uint32) {
	s.sessionDataMtx.Lock()
	defer s.sessionDataMtx.Unlock()

	delete(s.sessionData, id)
}

// OpenStream attempts to open a stream with a handler.
func (s *Session) OpenStream(streamType EStreamType) (handler StreamHandler, err error) {
	handlerBuilder, ok := StreamHandlerBuilders[streamType]
	if !ok {
		return nil, fmt.Errorf("Unknown stream type: %s", streamType)
	}

	l := log.WithField("streamType", streamType.String())
	l.Debug("Opening stream")
	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, err
	}

	streamId := stream.StreamID()
	l = l.WithField("stream", uint32(streamId))
	l.Debug("Stream opened")

	rw := packet.NewPacketReadWriter(stream)
	err = rw.WritePacket(&StreamInit{StreamType: streamType})
	if err != nil {
		return nil, err
	}

	handler, err = handlerBuilder.BuildHandler(&StreamHandlerConfig{
		Initiator: true,
		Log:       log.WithField("stream", uint32(streamId)),
		Session:   s,
		PacketRw:  rw,
		Stream:    stream,
	})
	if err != nil {
		return nil, err
	}

	go s.runStreamHandler(streamId, handler)
	return handler, nil
}
