package circuit

import (
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/session"
)

// CircuitBuilder manages building circuits with a peer.
type CircuitBuilder struct {
	peerIdentity *identity.Identity
	handleStream chan *session.Session
}

// CircuitBuilderManager handles requests from the CircuitBuilder.
type CircuitBuilderManager interface {
	// ForEachSession locks the session list and
	ForEachSession()
}

// NewCircuitBuilder creates a CircuitBuilder from a peer.
func NewCircuitBuilder(session *session.Session, peer *identity.Identity) *CircuitBuilder {
	cb := &CircuitBuilder{
		peerIdentity: peer,
	}
	return cb
}
