package session

import (
	"context"
	"errors"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/lucas-clemente/quic-go"
)

// Inactivity timeout (requires keep-alives)
var inactivityTimeout = time.Duration(5 * time.Second)

// Session manages a connection with a remote peer.
type Session struct {
	initiator       bool
	log             *log.Entry
	pumpErrors      chan error
	manager         SessionManager
	context         context.Context
	session         quic.Session
	controllers     map[uint32]Controller
	controlStream   quic.Stream
	inactivityTimer *time.Timer
}

// SessionManager manages a session.
type SessionManager interface {
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
		context:         config.Context,
		session:         config.Session,
		initiator:       config.Initiator,
		inactivityTimer: time.NewTimer(inactivityTimeout),
		log:             log.WithField("remote", config.Session.RemoteAddr().String()),
		pumpErrors:      make(chan error, 2),
	}
	if config.Initiator {
		if err := s.openControlStream(); err != nil {
			return nil, err
		}
	}
	s.startPump(s.acceptStreamPump)
	go s.manageCloseConditions()
	return s, nil
}

// resetInactivity resets the inactivity timer.
func (s *Session) resetInactivity() {
	s.inactivityTimer.Reset(inactivityTimeout)
}

// handleIncomingStream handles an incoming quic stream.
func (s *Session) handleIncomingStream(stream quic.Stream) error {
	l := s.log.WithField("stream", int(stream.StreamID()))
	if s.controlStream == nil {
		l.Debug("Control stream opened")
		s.controlStream = stream
		s.startPump(s.controlStreamHandler)
		return nil
	}

	l.Debug("Stream opened")
	// determine what kind of stream this is.
	return nil
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

// openControlStream opens the control channel as the initiator.
func (s *Session) openControlStream() error {
	stream, err := s.session.OpenStream()
	if err != nil {
		return err
	}
	l := s.log.WithField("stream", int(stream.StreamID()))
	l.Debug("Control stream opened")
	s.controlStream = stream
	stream.Write([]byte("hello"))
	return nil
}
