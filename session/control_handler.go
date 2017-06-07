package session

import (
	"context"
	// "github.com/lucas-clemente/quic-go"
	// "github.com/lucas-clemente/quic-go/protocol"
)

// controlStreamHandler manages control stream messages.
func (s *Session) controlStreamHandler() error {
	<-s.context.Done()
	return context.Canceled
}
