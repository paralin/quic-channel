package circuit

import (
	"context"

	"github.com/fuserobotics/quic-channel/session"
	"github.com/lucas-clemente/quic-go"
)

// BuildCircuitSession builds a session in the manager given a quic session.
func BuildCircuitSession(ctx context.Context, sess quic.Session, initiator bool, manager session.SessionManager) (*session.Session, error) {
	s, err := session.NewSession(session.SessionConfig{
		Context:         ctx,
		Manager:         manager,
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
