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

	streamHandlersMtx     sync.Mutex
	streamHandlers        map[protocol.StreamID]StreamHandler
	streamHandlerBuilders StreamHandlerBuilders

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
	// Stream handler builders
	HandlerBuilders StreamHandlerBuilders
}

// NewSession builds a new session.
func NewSession(config SessionConfig) (*Session, error) {
	s := &Session{
		started:               time.Now(),
		context:               config.Context,
		session:               config.Session,
		initiator:             config.Initiator,
		manager:               config.Manager,
		inactivityTimeout:     handshakeTimeout,
		streamHandlerBuilders: config.HandlerBuilders,
		inactivityTimer:       time.NewTimer(handshakeTimeout),
		pumpErrors:            make(chan error, 2),
		sessionData:           make(map[uint32]interface{}),
		streamHandlers:        make(map[protocol.StreamID]StreamHandler),
		log:                   log.WithField("remote", config.Session.RemoteAddr().String()),
	}
	s.childContext, s.childContextCancel = context.WithCancel(config.Context)
	s.StartPump(s.acceptStreamPump)
	go s.manageCloseConditions()
	return s, nil
}

// IsInitiator returns if the session was initiated by the local host.
func (s *Session) IsInitiator() bool {
	return s.initiator
}

// GetStartTime returns the time the session started.
func (s *Session) GetStartTime() time.Time {
	return s.started
}

// GetManager returns the SessionManager for this session
func (s *Session) GetManager() SessionManager {
	return s.manager
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

// DeleteData removes data from the session data store.
func (s *Session) DeleteData(id uint32) {
	s.sessionDataMtx.Lock()
	defer s.sessionDataMtx.Unlock()

	delete(s.sessionData, id)
}

// OpenStream attempts to open a stream with a handler.
func (s *Session) OpenStream(streamType StreamType) (handler StreamHandler, err error) {
	handlerBuilder, ok := s.streamHandlerBuilders[streamType]
	if !ok {
		return nil, fmt.Errorf("Unknown stream type: %d", streamType)
	}

	l := log.WithField("streamType", streamType)
	l.Debug("Opening stream")
	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, err
	}

	streamId := stream.StreamID()
	l = l.WithField("stream", uint32(streamId))
	l.Debug("Stream opened")

	rw := packet.NewPacketReadWriter(stream)
	err = rw.WritePacket(&StreamInit{StreamType: uint32(streamType)})
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

// handleIncomingStream handles an incoming quic stream.
func (s *Session) handleIncomingStream(stream quic.Stream) error {
	l := s.log.WithField("stream", int(stream.StreamID()))

	l.Debug("Stream opened")
	rw := packet.NewPacketReadWriter(stream)
	si := &StreamInit{}
	_, err := rw.ReadPacket(func(packetType packet.PacketType) (packet.Packet, error) {
		if packetType != 1 {
			return nil, fmt.Errorf("Expected packet type 1, got %d", packetType)
		}
		return si, nil
	})
	if err != nil {
		return err
	}

	handlerBuilder, ok := s.streamHandlerBuilders[StreamType(si.StreamType)]
	if !ok {
		return fmt.Errorf("Unknown stream type: %d", si.StreamType)
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

	l.WithField("streamType", si.StreamType).Debug("Stream initialized")
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

// StartPump starts a goroutine that will end the session if returned.
func (s *Session) StartPump(pump func() error) {
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
