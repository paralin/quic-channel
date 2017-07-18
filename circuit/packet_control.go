package circuit

import (
	"github.com/fuserobotics/quic-channel/handshake"
	"github.com/fuserobotics/quic-channel/packet"
)

// ProtoPacketType returns the packet type of the stream init packet.
func (p *KeepAlive) GetPacketType() packet.PacketType {
	return 4
}

// ProtoPacketType returns the packet type of the stream init packet.
func (p *CircuitProbe) GetPacketType() packet.PacketType {
	return 5
}

// ProtoPacketType returns the packet type of the stream init packet.
func (p *CircuitPeerLookupRequest) GetPacketType() packet.PacketType {
	return 6
}

// ProtoPacketType returns the packet type of the stream init packet.
func (p *CircuitPeerLookupResponse) GetPacketType() packet.PacketType {
	return 7
}

// ControlPacketIdentifier identifies Control packets.
var ControlPacketIdentifier = packet.NewPacketIdentifier()

func init() {
	err := handshake.AddPacketTypes(ControlPacketIdentifier)
	if err == nil {
		err = ControlPacketIdentifier.AddPacketType(
			func() packet.ProtoPacket { return &KeepAlive{} },
			func() packet.ProtoPacket { return &CircuitProbe{} },
			func() packet.ProtoPacket { return &CircuitPeerLookupRequest{} },
			func() packet.ProtoPacket { return &CircuitPeerLookupResponse{} },
		)
	}
	if err != nil {
		panic(err)
	}
}
