package node

import (
	"github.com/fuserobotics/quic-channel/session"
)

// nodeSessionHandler handles session events.
// It is separate from Node to hide it from the API surface.
type nodeSessionHandler struct {
	*Node
}

// OnSessionClosed is called when a session is closed.
func (n *nodeSessionHandler) OnSessionClosed(s *session.Session, err error) {
}

// OnSessionReady is called when the session is finished initializing.
// Returning an error will terminate the session with the error.
func (n *nodeSessionHandler) OnSessionReady(details *session.SessionReadyDetails) error {
	// TODO: Check if we need to kill this session as a duplicate.
	return nil
}
