package packet

import (
	"github.com/golang/protobuf/proto"
)

// PacketMaxLength is the estimated maximum length of a packet.
var PacketMaxLength = uint32(10000)

// PacketType represents what type of packet one is.
type PacketType uint32

// PacketIdentifierFunc identifies packets by ID, returning a message instance or error.
type PacketIdentifierFunc func(packetType PacketType) (Packet, error)

// Packet is a message with a type ID.
type Packet interface {
	proto.Message

	// PacketType returns the type ID of the packet.
	GetPacketType() PacketType
}
