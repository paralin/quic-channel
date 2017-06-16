package circuit

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// PacketType returns the packet type of the stream init packet.
func (p *SessionInitChallenge) GetPacketType() packet.PacketType {
	return 2
}

// PacketType returns the packet type of the stream init packet.
func (p *SessionInitResponse) GetPacketType() packet.PacketType {
	return 3
}

// PacketType returns the packet type of the stream init packet.
func (p *KeepAlive) GetPacketType() packet.PacketType {
	return 4
}

// ControlPacketIdentifier identifies Control packets.
var PacketIdentifier = packet.NewPacketIdentifier()

func init() {
	PacketIdentifier.AddPacketType(
		func() packet.Packet { return &SessionInitChallenge{} },
		func() packet.Packet { return &SessionInitResponse{} },
		func() packet.Packet { return &KeepAlive{} },
	)
}
