package circuit

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// PacketType returns the packet type of the stream init packet.
func (p *SessionInit) GetPacketType() packet.PacketType {
	return 2
}

// PacketType returns the packet type of the stream init packet.
func (p *KeepAlive) GetPacketType() packet.PacketType {
	return 3
}

// ControlPacketIdentifier identifies Control packets.
var PacketIdentifier = packet.NewPacketIdentifier()

func init() {
	PacketIdentifier.AddPacketType(
		func() packet.Packet { return &SessionInit{} },
		func() packet.Packet { return &KeepAlive{} },
	)
}
