package channel

import (
	"net"
)

// type assertion: Channel should implement net.PacketConn
var channelPacketConnAssertion net.PacketConn = &Channel{}
