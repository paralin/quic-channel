package node

import (
	"github.com/fuserobotics/quic-channel/session"
)

// nodeSessionHandler handles session events.
type nodeSessionHandler struct {
	*Node
}

// OnSessionClosed is called when a session is closed.
func (n *nodeSessionHandler) OnSessionClosed(s *session.Session, err error) {
}
