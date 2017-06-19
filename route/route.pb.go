// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/route/route.proto
// DO NOT EDIT!

/*
Package route is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/route/route.proto

It has these top-level messages:
	Route
	RouteEstablish
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
	// Destination is the destination of the route.
	// Source can be inferred from the first hop.
	Destination *identity.PeerIdentifier `protobuf:"bytes,2,opt,name=destination" json:"destination,omitempty"`
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

func (m *Route) GetDestination() *identity.PeerIdentifier {
	if m != nil {
		return m.Destination
	}
	return nil
}

// Hop is a hop in the probe route.
type Route_Hop struct {
	// Identity contains the identity of the peer.
	Identity *identity.PeerIdentifier `protobuf:"bytes,1,opt,name=identity" json:"identity,omitempty"`
	// BackwardInterface is the interface in the direction of the originator, used for session routing.
	BackwardInterface uint32 `protobuf:"varint,2,opt,name=backward_interface,json=backwardInterface" json:"backward_interface,omitempty"`
	// ForwardInterface is the interface in the direction of the destination, used for verification.
	ForwardInterface uint32 `protobuf:"varint,3,opt,name=forward_interface,json=forwardInterface" json:"forward_interface,omitempty"`
	// Timestamp is the time the route probe was processed.
	Timestamp uint64 `protobuf:"varint,4,opt,name=timestamp" json:"timestamp,omitempty"`
	// SegmentHash is the hash of the route segments before this hop.
	SegmentHash *signature.DataHash `protobuf:"bytes,5,opt,name=segment_hash,json=segmentHash" json:"segment_hash,omitempty"`
	// Next is the identifier for the next peer.
	Next *identity.PeerIdentifier `protobuf:"bytes,6,opt,name=next" json:"next,omitempty"`
}

func (m *Route_Hop) Reset()                    { *m = Route_Hop{} }
func (m *Route_Hop) String() string            { return proto.CompactTextString(m) }
func (*Route_Hop) ProtoMessage()               {}
func (*Route_Hop) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

func (m *Route_Hop) GetIdentity() *identity.PeerIdentifier {
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

func (m *Route_Hop) GetSegmentHash() *signature.DataHash {
	if m != nil {
		return m.SegmentHash
	}
	return nil
}

func (m *Route_Hop) GetNext() *identity.PeerIdentifier {
	if m != nil {
		return m.Next
	}
	return nil
}

// RouteEstablish is a agreement of a route by all peers.
type RouteEstablish struct {
	// Route is the encoded complete route.
	Route []byte `protobuf:"bytes,1,opt,name=route,proto3" json:"route,omitempty"`
	// Route signatures, in order of destination -> source.
	// The message field will be empty, should be filled from the ..route field.
	RouteSignatures []*signature.SignedMessage `protobuf:"bytes,2,rep,name=route_signatures,json=routeSignatures" json:"route_signatures,omitempty"`
}

func (m *RouteEstablish) Reset()                    { *m = RouteEstablish{} }
func (m *RouteEstablish) String() string            { return proto.CompactTextString(m) }
func (*RouteEstablish) ProtoMessage()               {}
func (*RouteEstablish) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *RouteEstablish) GetRoute() []byte {
	if m != nil {
		return m.Route
	}
	return nil
}

func (m *RouteEstablish) GetRouteSignatures() []*signature.SignedMessage {
	if m != nil {
		return m.RouteSignatures
	}
	return nil
}

func init() {
	proto.RegisterType((*Route)(nil), "route.Route")
	proto.RegisterType((*Route_Hop)(nil), "route.Route.Hop")
	proto.RegisterType((*RouteEstablish)(nil), "route.RouteEstablish")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/route/route.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 364 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x92, 0xc1, 0x4e, 0xea, 0x40,
	0x14, 0x86, 0x53, 0x0a, 0xe4, 0xde, 0x81, 0x7b, 0x85, 0xd1, 0xc5, 0x84, 0xb8, 0x20, 0xac, 0x88,
	0x0a, 0x24, 0x6a, 0x58, 0x18, 0xe3, 0x46, 0x4d, 0x60, 0x61, 0x62, 0xca, 0x03, 0x90, 0x69, 0x7b,
	0xda, 0x4e, 0xa0, 0x33, 0x75, 0xe6, 0x34, 0xea, 0x43, 0xf8, 0x04, 0xbe, 0xac, 0x61, 0x0a, 0x2d,
	0x71, 0x03, 0x9b, 0xe6, 0xfc, 0x3d, 0xdf, 0x3f, 0xfd, 0x3b, 0xe7, 0x90, 0x69, 0x2c, 0x30, 0xc9,
	0xfd, 0x71, 0xa0, 0xd2, 0x49, 0x94, 0x1b, 0xd0, 0xca, 0x57, 0x28, 0x02, 0x33, 0x79, 0xcb, 0x45,
	0x30, 0x0a, 0x12, 0x2e, 0x25, 0xac, 0x27, 0x5a, 0xe5, 0x08, 0xc5, 0x73, 0x9c, 0x69, 0x85, 0x8a,
	0x36, 0xac, 0xe8, 0xdd, 0x1f, 0x65, 0x17, 0x21, 0x48, 0x14, 0xf8, 0x59, 0x16, 0xc5, 0x21, 0xbd,
	0x87, 0xa3, 0xdc, 0x46, 0xc4, 0x92, 0x63, 0xae, 0xa1, 0xaa, 0x0a, 0xff, 0xe0, 0xcb, 0x25, 0x0d,
	0x6f, 0x93, 0x83, 0x5e, 0x10, 0x37, 0x51, 0x19, 0x73, 0xfa, 0xee, 0xb0, 0x75, 0xcd, 0xc6, 0x15,
	0xb8, 0x10, 0xb1, 0x84, 0xf0, 0x05, 0x8c, 0xe1, 0x31, 0x78, 0x1b, 0x88, 0xde, 0x91, 0x56, 0x08,
	0x06, 0x85, 0xe4, 0x28, 0x94, 0x64, 0xb5, 0xbe, 0x63, 0x3d, 0x65, 0xb6, 0x57, 0x00, 0x3d, 0xb7,
	0x22, 0x12, 0xa0, 0xbd, 0x7d, 0xb8, 0xf7, 0x5d, 0x23, 0xee, 0x4c, 0x65, 0xf4, 0x96, 0xfc, 0xd9,
	0xf1, 0xcc, 0x39, 0x70, 0x40, 0x49, 0xd2, 0x11, 0xa1, 0x3e, 0x0f, 0x56, 0xef, 0x5c, 0x87, 0x4b,
	0x21, 0x11, 0x74, 0xc4, 0x03, 0xb0, 0x01, 0xfe, 0x79, 0xdd, 0x5d, 0x67, 0xbe, 0x6b, 0xd0, 0x4b,
	0xd2, 0x8d, 0x94, 0xfe, 0x45, 0xbb, 0x96, 0xee, 0x6c, 0x1b, 0x15, 0x7c, 0x4e, 0xfe, 0xa2, 0x48,
	0xc1, 0x20, 0x4f, 0x33, 0x56, 0xef, 0x3b, 0xc3, 0xba, 0x57, 0xbd, 0xa0, 0x53, 0xd2, 0x36, 0x10,
	0xa7, 0x20, 0x71, 0x99, 0x70, 0x93, 0xb0, 0x86, 0xcd, 0x7c, 0xba, 0x77, 0x51, 0x4f, 0x1c, 0xf9,
	0x8c, 0x9b, 0xc4, 0x6b, 0x6d, 0xc1, 0x8d, 0xa0, 0x57, 0xa4, 0x2e, 0xe1, 0x03, 0x59, 0xf3, 0xc0,
	0x3f, 0x5a, 0x6a, 0xb0, 0x22, 0xff, 0xed, 0x38, 0x9e, 0x0d, 0x72, 0x7f, 0x2d, 0x4c, 0x42, 0xcf,
	0x48, 0xb1, 0x28, 0xf6, 0x92, 0xda, 0x5e, 0x21, 0xe8, 0x23, 0xe9, 0xd8, 0x62, 0x59, 0x7e, 0xde,
	0xb0, 0xda, 0x81, 0xd1, 0x9d, 0x58, 0xc7, 0xa2, 0x34, 0xf8, 0x4d, 0xbb, 0x03, 0x37, 0x3f, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x4f, 0x51, 0xc1, 0x61, 0xc2, 0x02, 0x00, 0x00,
}
