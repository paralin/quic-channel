package network

import "net"

// BoundPacketConn is a PacketConn with a RemoteAddr function.
type BoundPacketConn interface {
	net.PacketConn

	// RemoteAddr returns the bound remote address.
	RemoteAddr() net.Addr
}
