package circuit

import (
	"context"
	"crypto/x509"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/lucas-clemente/quic-go"
)

// BuildCircuitSession builds a session in the manager given a quic session.
func BuildCircuitSession(
	ctx context.Context,
	sess quic.Session,
	initiator bool,
	manager session.SessionManager,
	localIdentity *identity.ParsedIdentity,
	caCert *x509.Certificate,
) (*session.Session, error) {
	nsess, err := session.NewSession(session.SessionConfig{
		Context:         ctx,
		Manager:         manager,
		Initiator:       initiator,
		Session:         sess,
		HandlerBuilders: StreamHandlerBuilders,
		LocalIdentity:   localIdentity,
		CaCertificate:   caCert,
	})
	if err != nil {
		return nil, err
	}
	if !initiator {
		_, err := nsess.OpenStream(session.StreamType(EStreamType_STREAM_CONTROL))
		if err != nil {
			return nil, err
		}
	}
	return nsess, nil
}
