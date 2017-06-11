package session

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// PacketType returns the packet type of the stream init packet.
func (p *ControlSessionInit) PacketType() uint32 {
	return 2
}

// PacketType returns the packet type of the stream init packet.
func (p *ControlKeepAlive) PacketType() uint32 {
	return 3
}

// ControlPacketIdentifier identifies Control packets.
var ControlPacketIdentifier = packet.NewPacketIdentifier()

func init() {
	ControlPacketIdentifier.AddPacketType(
		func() packet.Packet { return &ControlSessionInit{} },
		func() packet.Packet { return &ControlKeepAlive{} },
	)
}
