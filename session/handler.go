package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
)

// StreamType is the type of stream.
type StreamType uint32

// StreamHandler manages a stream.
type StreamHandler interface {
	// Handle returns when the stream closes.
	Handle(ctx context.Context) error
	// StreamType returns the type of stream this handles.
	StreamType() StreamType
}

// StreamHandlerConfig are parameters passed to a StreamHandler.
type StreamHandlerConfig struct {
	// Are we the initiator of the stream?
	Initiator bool
	// Log is a log entry to use to log.
	Log *log.Entry
	// Session is the session for the stream.
	Session *Session
	// NetSession is the underlying network session.
	NetSession netproto.Session
	// Stream to handle.
	Stream netproto.Stream
	// Packet Read/Writer
	PacketRw *packet.PacketReadWriter
	// Local identity, with private key.
	LocalIdentity *identity.ParsedIdentity
	// CaCert is the CA certificate.
	CaCert *x509.Certificate
	// TLSConfig is the local TLS config.
	TLSConfig *tls.Config
}

// StreamHandlerBuilder constructs StreamHandlers.
type StreamHandlerBuilder interface {
	// BuildHandler constructs the handler,
	BuildHandler(ctx context.Context, config *StreamHandlerConfig) (StreamHandler, error)
}

// StreamHandlerBuilders is a map of stream type to stream handler.
type StreamHandlerBuilders map[StreamType]StreamHandlerBuilder
