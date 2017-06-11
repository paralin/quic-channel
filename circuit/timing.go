package circuit

import (
	"time"
)

// inactivityTimeout is the time allowed for inactivity after the handshake
var inactivityTimeout = time.Duration(5) * time.Second

// keepAliveFrequency is how often we send a keep alive packet.
var keepAliveFrequency = time.Duration(1) * time.Second
