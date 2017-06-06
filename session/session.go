package session

import (
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
)

// Session manages a connection with a remote peer.
type Session struct {
	session        quic.Session
	controllers    map[uint32]Controller
	streamHandlers map[protocol.StreamID]StreamHandler
}

// SessionConfig passes configuration to a session.
type SessionConfig struct {
}

// NewSession builds a new session.
func NewSession() (*Session, error) {
	return nil, nil
}
