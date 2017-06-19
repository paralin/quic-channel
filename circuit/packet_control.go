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

// PacketType returns the packet type of the stream init packet.
func (p *CircuitProbe) GetPacketType() packet.PacketType {
	return 5
}

// PacketType returns the packet type of the stream init packet.
func (p *CircuitPeerLookupRequest) GetPacketType() packet.PacketType {
	return 6
}

// PacketType returns the packet type of the stream init packet.
func (p *CircuitPeerLookupResponse) GetPacketType() packet.PacketType {
	return 7
}

// ControlPacketIdentifier identifies Control packets.
var ControlPacketIdentifier = packet.NewPacketIdentifier()

func init() {
	ControlPacketIdentifier.AddPacketType(
		func() packet.Packet { return &SessionInitChallenge{} },
		func() packet.Packet { return &SessionInitResponse{} },
		func() packet.Packet { return &KeepAlive{} },
		func() packet.Packet { return &CircuitProbe{} },
		func() packet.Packet { return &CircuitPeerLookupRequest{} },
		func() packet.Packet { return &CircuitPeerLookupResponse{} },
	)
}
