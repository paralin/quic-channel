// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/fuserobotics/quic-channel/session/session.proto

/*
Package session is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/session/session.proto

It has these top-level messages:
	StreamInit
*/
package session

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

// StreamInit initializes a stream.
// packet_type: 1, expected as first message on stream
type StreamInit struct {
	// Stream type is the kind of the stream.
	StreamType uint32 `protobuf:"varint,1,opt,name=stream_type,json=streamType" json:"stream_type,omitempty"`
}

func (m *StreamInit) Reset()                    { *m = StreamInit{} }
func (m *StreamInit) String() string            { return proto.CompactTextString(m) }
func (*StreamInit) ProtoMessage()               {}
func (*StreamInit) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *StreamInit) GetStreamType() uint32 {
	if m != nil {
		return m.StreamType
	}
	return 0
}

func init() {
	proto.RegisterType((*StreamInit)(nil), "session.StreamInit")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/session/session.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 126 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4a, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x2b, 0x2d, 0x4e, 0x2d, 0xca, 0x4f, 0xca, 0x2f,
	0xc9, 0x4c, 0x2e, 0xd6, 0x2f, 0x2c, 0xcd, 0x4c, 0xd6, 0x4d, 0xce, 0x48, 0xcc, 0xcb, 0x4b, 0xcd,
	0xd1, 0x2f, 0x4e, 0x2d, 0x2e, 0xce, 0xcc, 0xcf, 0x83, 0xd1, 0x7a, 0x05, 0x45, 0xf9, 0x25, 0xf9,
	0x42, 0xec, 0x50, 0xae, 0x92, 0x2e, 0x17, 0x57, 0x70, 0x49, 0x51, 0x6a, 0x62, 0xae, 0x67, 0x5e,
	0x66, 0x89, 0x90, 0x3c, 0x17, 0x77, 0x31, 0x98, 0x17, 0x5f, 0x52, 0x59, 0x90, 0x2a, 0xc1, 0xa8,
	0xc0, 0xa8, 0xc1, 0x1b, 0xc4, 0x05, 0x11, 0x0a, 0xa9, 0x2c, 0x48, 0x4d, 0x62, 0x03, 0x6b, 0x37,
	0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xa4, 0x8f, 0xa6, 0x95, 0x7c, 0x00, 0x00, 0x00,
}
