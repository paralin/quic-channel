package packet

import (
	"fmt"
)

// PacketIdentifier stores packet types and identifies them.
type PacketIdentifier struct {
	packetConstructors map[PacketType]func() Packet
}

// NewPacketIdentifier builds a new packet identifier.
func NewPacketIdentifier() *PacketIdentifier {
	return &PacketIdentifier{packetConstructors: make(map[PacketType]func() Packet)}
}

// AddPacketType adds a packet constructor to the identifier.
func (i *PacketIdentifier) AddPacketType(constructors ...func() Packet) {
	for _, constructor := range constructors {
		sample := constructor()
		i.packetConstructors[sample.GetPacketType()] = constructor
	}
}

// IdentifyPacket identifies the packet for the decoder.
func (i *PacketIdentifier) IdentifyPacket(packetType PacketType) (Packet, error) {
	constructor, ok := i.packetConstructors[packetType]
	if !ok {
		return nil, fmt.Errorf("Unexpected packet type %d", packetType)
	}
	return constructor(), nil
}
