package packet

import (
	"fmt"
)

// rawPacketIdentifyFunc returns nil.
var rawPacketIdentifyFunc = func() ProtoPacket { return nil }

// PacketIdentifier stores packet types and identifies them.
type PacketIdentifier struct {
	packetConstructors map[PacketType]func() ProtoPacket
}

// NewPacketIdentifier builds a new packet identifier.
func NewPacketIdentifier() *PacketIdentifier {
	return &PacketIdentifier{packetConstructors: make(map[PacketType]func() ProtoPacket)}
}

// AddPacketType adds a packet constructor to the identifier.
func (i *PacketIdentifier) AddPacketType(constructors ...func() ProtoPacket) error {
	for _, constructor := range constructors {
		sample := constructor()
		pktType := sample.GetPacketType()
		if old, ok := i.packetConstructors[pktType]; ok {
			return fmt.Errorf("Duplicate packet type: %#v and %#v", sample, old())
		}
		i.packetConstructors[pktType] = constructor
	}

	return nil
}

// AddRawPacketType adds a packet which is not parsed.
func (i *PacketIdentifier) AddRawPacketType(pktTypes ...PacketType) error {
	for _, pktType := range pktTypes {
		if old, ok := i.packetConstructors[pktType]; ok {
			return fmt.Errorf("Duplicate packet type: %#v and %#v", pktType, old())
		}
		i.packetConstructors[pktType] = rawPacketIdentifyFunc
	}

	return nil
}

// IdentifyPacket identifies the packet for the decoder.
func (i *PacketIdentifier) IdentifyPacket(packetType PacketType) (ProtoPacket, error) {
	constructor, ok := i.packetConstructors[packetType]
	if !ok {
		return nil, fmt.Errorf("Unexpected packet type %d", packetType)
	}
	return constructor(), nil
}
