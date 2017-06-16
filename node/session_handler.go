package node

import (
	"github.com/fuserobotics/quic-channel/session"
)

// nodeSessionHandler handles session callbacks.
type nodeSessionHandler struct {
	*Node
}

// OnSessionReady is called when the session is finished initializing.
// Returning an error will terminate the session with the error.
func (h *nodeSessionHandler) OnSessionReady(details *session.SessionReadyDetails) error {
	// Iterate over existing sessions.
	return nil
}

// OnSessionClosed is called when a session is closed.
func (h *nodeSessionHandler) OnSessionClosed(sess *session.Session, err error) {
}
