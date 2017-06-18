package route

import (
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/timestamp"
)

// hopSignatureSaltLen is the length of the salt for the hop signature.
// Usually none, since timestamp is variable anyway.
var hopSignatureSaltLen int = 0

// NewHop builds a new hop.
func NewHop(ourIdent *identity.Identity, nextIdent *identity.PeerIdentifier) *Route_Hop {
	return &Route_Hop{
		Identity:  ourIdent,
		Next:      nextIdent,
		Timestamp: timestamp.Now(), // overwritten later-
	}
}
