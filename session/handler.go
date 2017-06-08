package session

import (
	"context"

	log "github.com/Sirupsen/logrus"
	"github.com/lucas-clemente/quic-go"
)

// StreamHandler manages a stream.
type StreamHandler interface {
	// Handle returns when the stream closes.
	Handle(ctx context.Context) error
	// StreamType returns the type of stream this handles.
	StreamType() EStreamType
}

// StreamHandlerConfig are parameters passed to a StreamHandler.
type StreamHandlerConfig struct {
	// Are we the initiator of the stream?
	Initiator bool
	// Log is a log entry to use to log.
	Log *log.Entry
	// Session is the session for the stream.
	Session *Session
	// Stream to handle.
	Stream quic.Stream
	// Packet Read/Writer
	PacketRw *PacketReadWriter
}

// StreamHandlerBuilder constructs StreamHandlers.
type StreamHandlerBuilder interface {
	// BuildHandler constructs the handler,
	BuildHandler(config *StreamHandlerConfig) (StreamHandler, error)
}

// StreamHandlerBuilders are stream handler builders for each stream type.
var StreamHandlerBuilders = map[EStreamType]StreamHandlerBuilder{
	EStreamType_STREAM_CONTROL: &controlStreamHandlerBuilder{},
}
