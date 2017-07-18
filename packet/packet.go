package packet

import (
	"bytes"

	"github.com/golang/protobuf/proto"
)

// PacketMaxLength is the estimated maximum length of a packet.
var PacketMaxLength = uint32(10000)

// PacketType represents what type of packet one is.
type PacketType uint32

// PacketIdentifierFunc identifies packets by ID, returning a message instance or error.
// Returning nil for the Packet and the error will result in the message being returned in a Buffer.
type PacketIdentifierFunc func(packetType PacketType) (ProtoPacket, error)

// Packet is a message with a type ID.
type Packet interface {
	// PacketType returns the type ID of the packet.
	GetPacketType() PacketType
}

// RawPacket represents a raw packet.
type RawPacket struct {
	packetType PacketType
	data       *bytes.Buffer
}

// ProtoPacket represents a protobuf packet.
type ProtoPacket interface {
	Packet
	proto.Message
}

// NewRawPacket builds a new raw packet.
func NewRawPacket(packetType PacketType, data *bytes.Buffer) *RawPacket {
	return &RawPacket{packetType: packetType, data: data}
}

// Len returns the length of the underlying buffer.
func (r *RawPacket) Len() int {
	return r.data.Len()
}

// Data returns the underlying buffer for the packet.
func (r *RawPacket) Data() *bytes.Buffer {
	return r.data
}

// GetPacketType returns the packet type.
func (r *RawPacket) GetPacketType() PacketType {
	return r.packetType
}
