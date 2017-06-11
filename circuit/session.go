package circuit

import (
	"context"

	"github.com/fuserobotics/quic-channel/session"
	"github.com/lucas-clemente/quic-go"
)

// CircuitSessionManager manages circuit sessions.
type CircuitSessionManager struct {
	context context.Context
}

// NewCircuitSessionManager builds a new CircuitSessionManager.
func NewCircuitSessionManager(ctx context.Context) *CircuitSessionManager {
	return &CircuitSessionManager{context: ctx}
}

// OnSessionClosed is called when a session is closed.
func (m *CircuitSessionManager) OnSessionClosed(s *session.Session, err error) {
}

// OnSessionReady is called when the session is finished initializing.
// Returning an error will terminate the session with the error.
func (m *CircuitSessionManager) OnSessionReady(details *session.SessionReadyDetails) error {
	return nil
}

// buildCircuitSession builds a session in the manager given a quic session.
func (m *CircuitSessionManager) BuildCircuitSession(sess quic.Session, initiator bool) (*session.Session, error) {
	s, err := session.NewSession(session.SessionConfig{
		Context:         m.context,
		Manager:         m,
		Initiator:       initiator,
		Session:         sess,
		HandlerBuilders: StreamHandlerBuilders,
	})
	if err == nil && initiator {
		handler, err := s.OpenStream(session.StreamType(EStreamType_STREAM_CONTROL))
		if err != nil {
			return nil, err
		}
		ch := handler.(*controlStreamHandler)
		if err := ch.SendSessionInit(s.GetStartTime()); err != nil {
			return nil, err
		}
	}
	return s, err
}
