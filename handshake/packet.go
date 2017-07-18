package handshake

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// ProtoPacketType returns the packet type of the stream init packet.
func (p *SessionInitChallenge) GetPacketType() packet.PacketType {
	return 2
}

// ProtoPacketType returns the packet type of the stream init packet.
func (p *SessionInitResponse) GetPacketType() packet.PacketType {
	return 3
}

// AddPacketTypes adds the Handshake packet types to an identifier.
func AddPacketTypes(ident *packet.PacketIdentifier) error {
	return ident.AddPacketType(
		func() packet.ProtoPacket { return &SessionInitChallenge{} },
		func() packet.ProtoPacket { return &SessionInitResponse{} },
	)
}
