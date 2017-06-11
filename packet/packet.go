package packet

import (
	"github.com/golang/protobuf/proto"
)

// PacketMaxLength is the estimated maximum length of a packet.
var PacketMaxLength = uint32(10000)

// Packet is a message with a type ID.
type Packet interface {
	proto.Message

	// PacketType returns the type ID of the packet.
	PacketType() uint32
}
