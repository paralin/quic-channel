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
func (i *CircuitEstablished) GetPacketType() packet.PacketType {
	return 3
}

// CircuitPacketType_InBand is the in_band packet type.
var CircuitPacketType_InBand = packet.PacketType(9)

func init() {
	err := CircuitPacketIdentifier.AddPacketType(
		func() packet.ProtoPacket { return &CircuitInit{} },
		func() packet.ProtoPacket { return &CircuitEstablished{} },
		func() packet.ProtoPacket { return &CircuitPeerLookupRequest{} },
		func() packet.ProtoPacket { return &CircuitPeerLookupResponse{} },
	)
	if err == nil {
		err = CircuitPacketIdentifier.AddRawPacketType(
			// CircuitPacket packet type
			CircuitPacketType_InBand,
		)
	}
	if err != nil {
		panic(err)
	}
}
