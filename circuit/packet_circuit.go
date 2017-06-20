package circuit

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// CircuitPacketIdentifier identifies Circuit packets.
var CircuitPacketIdentifier = packet.NewPacketIdentifier()

// PacketType returns the packet type of the stream init packet.
func (i *CircuitInit) GetPacketType() packet.PacketType {
	return 1
}

// PacketType returns the packet type of the stream init packet.
func (i *CircuitPacket) GetPacketType() packet.PacketType {
	return 2
}

// PacketType returns the packet type of the stream init packet.
func (i *CircuitEstablished) GetPacketType() packet.PacketType {
	return 3
}

func init() {
	err := CircuitPacketIdentifier.AddPacketType(
		func() packet.Packet { return &CircuitInit{} },
		func() packet.Packet { return &CircuitEstablished{} },
		func() packet.Packet { return &CircuitPacket{} },
		func() packet.Packet { return &CircuitPeerLookupRequest{} },
		func() packet.Packet { return &CircuitPeerLookupResponse{} },
	)
	if err != nil {
		panic(err)
	}
}
