// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/route/route.proto
// DO NOT EDIT!

/*
Package route is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/route/route.proto

It has these top-level messages:
	Route
*/
package route

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import identity "github.com/fuserobotics/quic-channel/identity"
import signature "github.com/fuserobotics/quic-channel/signature"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Route is a circuit probe route.
type Route struct {
	// Hops are the hop steps in the route.
	Hop []*signature.SignedMessage `protobuf:"bytes,1,rep,name=hop" json:"hop,omitempty"`
}

func (m *Route) Reset()                    { *m = Route{} }
func (m *Route) String() string            { return proto.CompactTextString(m) }
func (*Route) ProtoMessage()               {}
func (*Route) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Route) GetHop() []*signature.SignedMessage {
	if m != nil {
		return m.Hop
	}
	return nil
}

// Hop is a hop in the probe route.
type Route_Hop struct {
	// Identity contains the identity of the peer.
	Identity *identity.Identity `protobuf:"bytes,1,opt,name=identity" json:"identity,omitempty"`
	// BackwardInterface is the interface in the direction of the originator, used for session routing.
	BackwardInterface uint32 `protobuf:"varint,2,opt,name=backward_interface,json=backwardInterface" json:"backward_interface,omitempty"`
	// ForwardInterface is the interface in the direction of the destination, used for verification.
	ForwardInterface uint32 `protobuf:"varint,3,opt,name=forward_interface,json=forwardInterface" json:"forward_interface,omitempty"`
	// Timestamp is the time the route probe was processed.
	Timestamp uint64 `protobuf:"varint,4,opt,name=timestamp" json:"timestamp,omitempty"`
}

func (m *Route_Hop) Reset()                    { *m = Route_Hop{} }
func (m *Route_Hop) String() string            { return proto.CompactTextString(m) }
func (*Route_Hop) ProtoMessage()               {}
func (*Route_Hop) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

func (m *Route_Hop) GetIdentity() *identity.Identity {
	if m != nil {
		return m.Identity
	}
	return nil
}

func (m *Route_Hop) GetBackwardInterface() uint32 {
	if m != nil {
		return m.BackwardInterface
	}
	return 0
}

func (m *Route_Hop) GetForwardInterface() uint32 {
	if m != nil {
		return m.ForwardInterface
	}
	return 0
}

func (m *Route_Hop) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func init() {
	proto.RegisterType((*Route)(nil), "route.Route")
	proto.RegisterType((*Route_Hop)(nil), "route.Route.Hop")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/route/route.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 258 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x8f, 0xc1, 0x4a, 0xc4, 0x30,
	0x10, 0x86, 0x89, 0xdd, 0x15, 0xcd, 0x22, 0xb8, 0x39, 0x95, 0xe2, 0xa1, 0x78, 0x2a, 0xca, 0xa6,
	0xb0, 0x82, 0x27, 0xf1, 0xec, 0x1e, 0xbc, 0xc4, 0x07, 0x90, 0x34, 0x9d, 0xb6, 0x41, 0x9b, 0xd4,
	0x64, 0x82, 0xf8, 0x54, 0x3e, 0x95, 0xef, 0x21, 0xdb, 0x6e, 0x5b, 0xd8, 0xd3, 0x5e, 0xc2, 0x9f,
	0xf9, 0xbf, 0x7f, 0xf8, 0x87, 0x3e, 0xd6, 0x1a, 0x9b, 0x50, 0x70, 0x65, 0xdb, 0xbc, 0x0a, 0x1e,
	0x9c, 0x2d, 0x2c, 0x6a, 0xe5, 0xf3, 0xaf, 0xa0, 0xd5, 0x46, 0x35, 0xd2, 0x18, 0xf8, 0xcc, 0x9d,
	0x0d, 0x08, 0xc3, 0xcb, 0x3b, 0x67, 0xd1, 0xb2, 0x65, 0xff, 0x49, 0x9e, 0x4e, 0x8a, 0xeb, 0x12,
	0x0c, 0x6a, 0xfc, 0x99, 0xc4, 0xb0, 0x24, 0x79, 0x3e, 0x29, 0xed, 0x75, 0x6d, 0x24, 0x06, 0x07,
	0xb3, 0x1a, 0xf2, 0xb7, 0x7f, 0x84, 0x2e, 0xc5, 0xbe, 0x07, 0xbb, 0xa3, 0x51, 0x63, 0xbb, 0x98,
	0xa4, 0x51, 0xb6, 0xda, 0xc6, 0x7c, 0x06, 0xdf, 0x74, 0x6d, 0xa0, 0x7c, 0x05, 0xef, 0x65, 0x0d,
	0x62, 0x0f, 0x25, 0xbf, 0x84, 0x46, 0x2f, 0xb6, 0x63, 0x9c, 0x5e, 0x8c, 0x7d, 0x62, 0x92, 0x92,
	0x6c, 0xb5, 0x65, 0x7c, 0x2a, 0xb8, 0x3b, 0x08, 0x31, 0x31, 0x6c, 0x43, 0x59, 0x21, 0xd5, 0xc7,
	0xb7, 0x74, 0xe5, 0xbb, 0x36, 0x08, 0xae, 0x92, 0x0a, 0xe2, 0xb3, 0x94, 0x64, 0x57, 0x62, 0x3d,
	0x3a, 0xbb, 0xd1, 0x60, 0xf7, 0x74, 0x5d, 0x59, 0x77, 0x44, 0x47, 0x3d, 0x7d, 0x7d, 0x30, 0x66,
	0xf8, 0x86, 0x5e, 0xa2, 0x6e, 0xc1, 0xa3, 0x6c, 0xbb, 0x78, 0x91, 0x92, 0x6c, 0x21, 0xe6, 0x41,
	0x71, 0xde, 0x9f, 0xfb, 0xf0, 0x1f, 0x00, 0x00, 0xff, 0xff, 0xfd, 0xbd, 0xed, 0x33, 0xad, 0x01,
	0x00, 0x00,
}
