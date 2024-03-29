package circuit

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/session"
)

// BuildCircuitSession builds a session in the manager given a quic session.
func BuildCircuitSession(
	ctx context.Context,
	sess netproto.Session,
	manager session.SessionManager,
	localIdentity *identity.ParsedIdentity,
	caCert *x509.Certificate,
	tlsConfig *tls.Config,
) (*session.Session, error) {
	nsess, err := session.NewSession(session.SessionConfig{
		Context:         ctx,
		Manager:         manager,
		Session:         sess,
		HandlerBuilders: StreamHandlerBuilders,
		LocalIdentity:   localIdentity,
		CaCertificate:   caCert,
		TLSConfig:       tlsConfig,
	})
	if err != nil {
		return nil, err
	}

	if sess.Initiator() {
		_, err := nsess.OpenStream(session.StreamType(EStreamType_STREAM_CONTROL))
		if err != nil {
			return nil, err
		}
	}

	return nsess, nil
}
