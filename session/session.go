package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/network"
	"github.com/fuserobotics/quic-channel/packet"
)

// handshakeTimeout is the time allowed for a handshake.
var handshakeTimeout = 3 * time.Second

// sessionIdCtr assigns an integer id to sessions for logging
var sessionIdCtr int = 1

// Session manages a connection with a remote peer.
type Session struct {
	id                int
	context           context.Context
	log               *log.Entry
	started           time.Time
	manager           SessionManager
	session           netproto.Session
	pumpErrors        chan error
	inactivityTimer   *time.Timer
	inactivityTimeout time.Duration
	localIdentity     *identity.ParsedIdentity
	caCert            *x509.Certificate
	tlsConfig         *tls.Config
	inter             *network.NetworkInterface
	closedCallbacks   []func(s *Session, err error)

	childContext       context.Context
	childContextCancel context.CancelFunc

	streamHandlersMtx     sync.Mutex
	streamHandlers        map[uint32]StreamHandler
	streamHandlerBuilders StreamHandlerBuilders

	sessionDataMtx sync.Mutex
	sessionData    map[uint32]interface{}
}

// SessionReadyDetails contains information about the session becoming ready.
type SessionReadyDetails struct {
	// Session is the session that became ready.
	Session *Session
	// InitiatedTimestamp is when this session was initiated.
	InitiatedTimestamp time.Time
	// PeerIdentity is the parsed peer identity.
	PeerIdentity *identity.ParsedIdentity
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
	Session netproto.Session
	// Stream handler builders
	HandlerBuilders StreamHandlerBuilders
	// Identity of the local node
	LocalIdentity *identity.ParsedIdentity
	// CaCertificate is the CA cert.
	CaCertificate *x509.Certificate
	// TLSConfig is the local TLS config.
	TLSConfig *tls.Config
}

// NewSession builds a new session.
func NewSession(config SessionConfig) (*Session, error) {
	s := &Session{
		id:                    sessionIdCtr,
		started:               time.Now(),
		context:               config.Context,
		session:               config.Session,
		manager:               config.Manager,
		inactivityTimeout:     handshakeTimeout,
		streamHandlerBuilders: config.HandlerBuilders,
		inactivityTimer:       time.NewTimer(handshakeTimeout),
		pumpErrors:            make(chan error, 2),
		sessionData:           make(map[uint32]interface{}),
		streamHandlers:        make(map[uint32]StreamHandler),
		localIdentity:         config.LocalIdentity,
		log:                   log.WithField("session", sessionIdCtr),
		caCert:                config.CaCertificate,
		tlsConfig:             config.TLSConfig,
	}
	sessionIdCtr++
	if config.LocalIdentity == nil || config.LocalIdentity.GetPrivateKey() == nil {
		return nil, errors.New("local identity must be set with a private key")
	}
	localCertChain, err := config.LocalIdentity.ParseCertificates()
	if err != nil {
		return nil, err
	}
	if config.CaCertificate == nil {
		return nil, errors.New("ca certificate must be given")
	}
	if err := localCertChain.Validate(config.CaCertificate); err != nil {
		return nil, err
	}

	s.childContext, s.childContextCancel = context.WithCancel(config.Context)
	s.StartPump(s.acceptStreamPump)
	go s.manageCloseConditions()
	return s, nil
}

// IsInitiator returns if the session was initiated by the local host.
func (s *Session) IsInitiator() bool {
	return s.session.Initiator()
}

// GetId gets the incremented ID of this session
func (s *Session) GetId() int {
	return s.id
}

// GetStartTime returns the time the session started.
func (s *Session) GetStartTime() time.Time {
	return s.started
}

// SetStartTime overrides the built-in start time.
func (s *Session) SetStartTime(t time.Time) {
	s.started = t
}

// CloseWithErr forces the session to close early.
func (s *Session) CloseWithErr(err error) {
	select {
	case s.pumpErrors <- err:
	default:
	}
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
	if !ok && builder != nil {
		data = builder()
		if data == nil {
			return nil
		}
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
	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, err
	}

	streamId := stream.ID()
	l = l.WithField("stream", streamId)
	l.Debug("Stream opened (by us)")

	rw := packet.NewPacketReadWriter(stream)
	err = rw.WriteProtoPacket(&StreamInit{StreamType: uint32(streamType)})
	if err != nil {
		return nil, err
	}

	shConfig := s.buildBaseStreamHandlerConfig(true)
	shConfig.Log = s.log.WithField("stream", uint32(streamId))
	shConfig.Session = s
	shConfig.NetSession = s.session
	shConfig.PacketRw = rw
	shConfig.Stream = stream

	handler, err = handlerBuilder.BuildHandler(s.context, shConfig)
	if err != nil {
		return nil, err
	}

	go s.runStreamHandler(handler, stream)

	l.Debug("Stream initialized")
	return handler, nil
}

func (s *Session) buildBaseStreamHandlerConfig(initiator bool) *StreamHandlerConfig {
	return &StreamHandlerConfig{
		Initiator:     initiator,
		Session:       s,
		NetSession:    s.session,
		LocalIdentity: s.localIdentity,
		CaCert:        s.caCert,
		TLSConfig:     s.tlsConfig,
	}
}

// handleIncomingStream handles an incoming stream.
func (s *Session) handleIncomingStream(stream netproto.Stream) error {
	l := s.log.WithField("stream", stream.ID())

	l.Debug("Stream opened")
	rw := packet.NewPacketReadWriter(stream)
	si := &StreamInit{}
	_, _, err := rw.ReadPacket(func(packetType packet.PacketType) (packet.ProtoPacket, error) {
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

	shConfig := s.buildBaseStreamHandlerConfig(false)
	shConfig.Log = l
	shConfig.Session = s
	shConfig.PacketRw = rw
	shConfig.Stream = stream

	handler, err := handlerBuilder.BuildHandler(s.context, shConfig)
	if err != nil {
		return err
	}

	l.WithField("streamType", si.StreamType).Debug("Stream initialized")
	go s.runStreamHandler(handler, stream)

	return nil
}

// runStreamHandler manages a stream handler.
func (s *Session) runStreamHandler(handler StreamHandler, stream netproto.Stream) {
	id := stream.ID()
	s.streamHandlersMtx.Lock()
	s.streamHandlers[uint32(id)] = handler
	s.streamHandlersMtx.Unlock()

	ctx, ctxCancel := context.WithCancel(s.childContext)
	defer ctxCancel()

	err := handler.Handle(ctx)
	l := s.log.WithField("stream", uint32(id))

	select {
	case <-s.childContext.Done():
		return // Don't print or bother removing the stream handler when we're done with the session.
	default:
	}

	if err != nil && err != io.EOF && err != context.Canceled {
		l.WithError(err).Warn("Stream closed with error")
	} else {
		l.Debug("Stream closed")
	}

	s.streamHandlersMtx.Lock()
	delete(s.streamHandlers, uint32(id))
	s.streamHandlersMtx.Unlock()

	stream.Close()
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

// GetInterface attempts to determine the interface this session is running on.
func (s *Session) GetInterface() *network.NetworkInterface {
	if s.inter != nil {
		return s.inter
	}

	remAddr := s.session.RemoteAddr()
	uadr, ok := remAddr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	inter, _ := network.FromAddr(uadr.IP)
	s.inter = inter
	return inter
}

// GetLocalAddr returns the local address.
func (s *Session) GetLocalAddr() net.Addr {
	return s.session.LocalAddr()
}

// GetRemoteAddr returns the remote address.
func (s *Session) GetRemoteAddr() net.Addr {
	return s.session.RemoteAddr()
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

// AddCloseCallback adds a function to be called when the session closes.
func (s *Session) AddCloseCallback(cb func(s *Session, err error)) {
	s.closedCallbacks = append(s.closedCallbacks, cb)
}

// manageCloseConditions returns when the session closes.
func (s *Session) manageCloseConditions() (sessErr error) {
	defer func() {
		l := s.log
		if sessErr != nil {
			l = l.WithError(sessErr)
		}
		if s.childContextCancel != nil {
			s.childContextCancel()
		}
		for _, cb := range s.closedCallbacks {
			go cb(s, sessErr)
		}
		s.closedCallbacks = nil
		if s.session != nil {
			// s.session.Close(sessErr)
			s.session.Close()
		}
		if s.manager != nil {
			s.manager.OnSessionClosed(s, sessErr)
		}
		l.Debug("Session closed")
	}()

	s.log.
		WithField("addr", s.session.RemoteAddr().String()).
		WithField("initiator", s.session.Initiator()).
		Debug("Session started")

	select {
	case <-s.context.Done():
		return context.Canceled
	//case <-s.inactivityTimer.C: TODO: re-enable inactivity timeout
	// 	return errors.New("inactivity timeout reached")
	case err := <-s.pumpErrors:
		return err
	}
}
