package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/session"
)

// ChannelSessionMarker is used as the key for ChannelSessions on the peer.
var ChannelSessionMarker struct{ channelSessionMarker uint32 }

// ChannelSessionConfig configures a channel session.
type ChannelSessionConfig struct {
	// ExpectedPeerIdentity is the identity of the target peer.
	ExpectedPeerIdentity *identity.ParsedIdentity
}

// BuildChannelSession builds a session in the manager given a quic session.
func BuildChannelSession(
	ctx context.Context,
	sess netproto.Session,
	manager session.SessionManager,
	localIdentity *identity.ParsedIdentity,
	caCert *x509.Certificate,
	tlsConfig *tls.Config,
	sessConfig *ChannelSessionConfig,
) (*session.Session, error) {
	ctx = context.WithValue(ctx, "channelSessionConfig", sessConfig)
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
