package session

import (
	"github.com/lucas-clemente/quic-go"
)

// StreamHandler manages a stream on a session.
type StreamHandler interface {
}

// StreamHandlerBuilder provides StreamHandlers for opened streams.
type StreamHandlerBuilder interface {
	// BuildStreamHandler checks the session and builds a StreamHandler. If an error is returned, the session is closed.
	BuildStreamHandler(session *Session, stream quic.Stream) (StreamHandler, error)
}
