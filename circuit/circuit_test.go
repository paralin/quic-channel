package circuit

import (
	"net"
	// "testing"
)

// type assertion
var circuitIsPacketConn net.PacketConn = &Circuit{}
