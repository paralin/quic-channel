package route

import (
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/timestamp"
)

// hopSignatureSaltLen is the length of the salt for the hop signature.
// Usually none, since timestamp is variable anyway.
var hopSignatureSaltLen int = 0

// NewHop builds a new hop.
func NewHop(nextIdent *identity.PeerIdentifier) *Route_Hop {
	return &Route_Hop{
		Next:      nextIdent,
		Timestamp: timestamp.Now(), // overwritten later-
	}
}

// CompareTo checks if two Hop are equiv.
func (h *Route_Hop) CompareTo(other *Route_Hop) bool {
	return h.Identity.CompareTo(other.Identity) &&
		h.Next.CompareTo(other.Next) &&
		h.ForwardInterface == other.ForwardInterface &&
		h.BackwardInterface == other.BackwardInterface
}
