package circuit

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// PacketType returns the packet type of the stream init packet.
func (p *ControlSessionInit) GetPacketType() packet.PacketType {
	return 2
}

// PacketType returns the packet type of the stream init packet.
func (p *ControlKeepAlive) GetPacketType() packet.PacketType {
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
