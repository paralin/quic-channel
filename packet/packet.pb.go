// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/packet/packet.proto
// DO NOT EDIT!

/*
Package packet is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/packet/packet.proto

It has these top-level messages:
	PacketHeader
*/
package packet

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// PacketHeader is the fixed-length header to a packet.
type PacketHeader struct {
	// Length of the following Control packet.
	PacketLength uint32 `protobuf:"fixed32,1,opt,name=packet_length,json=packetLength" json:"packet_length,omitempty"`
	// Packet type is the kind of the following packet.
	PacketType uint32 `protobuf:"fixed32,2,opt,name=packet_type,json=packetType" json:"packet_type,omitempty"`
}

func (m *PacketHeader) Reset()                    { *m = PacketHeader{} }
func (m *PacketHeader) String() string            { return proto.CompactTextString(m) }
func (*PacketHeader) ProtoMessage()               {}
func (*PacketHeader) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *PacketHeader) GetPacketLength() uint32 {
	if m != nil {
		return m.PacketLength
	}
	return 0
}

func (m *PacketHeader) GetPacketType() uint32 {
	if m != nil {
		return m.PacketType
	}
	return 0
}

func init() {
	proto.RegisterType((*PacketHeader)(nil), "packet.PacketHeader")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/packet/packet.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 145 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xb2, 0x48, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x2b, 0x2d, 0x4e, 0x2d, 0xca, 0x4f, 0xca, 0x2f,
	0xc9, 0x4c, 0x2e, 0xd6, 0x2f, 0x2c, 0xcd, 0x4c, 0xd6, 0x4d, 0xce, 0x48, 0xcc, 0xcb, 0x4b, 0xcd,
	0xd1, 0x2f, 0x48, 0x4c, 0xce, 0x4e, 0x2d, 0x81, 0x52, 0x7a, 0x05, 0x45, 0xf9, 0x25, 0xf9, 0x42,
	0x6c, 0x10, 0x9e, 0x52, 0x08, 0x17, 0x4f, 0x00, 0x98, 0xe5, 0x91, 0x9a, 0x98, 0x92, 0x5a, 0x24,
	0xa4, 0xcc, 0xc5, 0x0b, 0x91, 0x89, 0xcf, 0x49, 0xcd, 0x4b, 0x2f, 0xc9, 0x90, 0x60, 0x54, 0x60,
	0xd4, 0x60, 0x0f, 0xe2, 0x81, 0x08, 0xfa, 0x80, 0xc5, 0x84, 0xe4, 0xb9, 0xb8, 0xa1, 0x8a, 0x4a,
	0x2a, 0x0b, 0x52, 0x25, 0x98, 0xc0, 0x4a, 0xb8, 0x20, 0x42, 0x21, 0x95, 0x05, 0xa9, 0x49, 0x6c,
	0x60, 0x4b, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xb4, 0xed, 0xe3, 0x99, 0xa0, 0x00, 0x00,
	0x00,
}
