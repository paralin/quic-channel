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
	Identity *identity.Identity `protobuf:"bytes,1,opt,name=identity" json:"identity,omitempty"`
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
	// 370 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x92, 0xc1, 0x6e, 0xda, 0x40,
	0x10, 0x86, 0x65, 0x0c, 0xa8, 0x5d, 0x68, 0x0b, 0xdb, 0x1e, 0x56, 0xa8, 0x07, 0xc4, 0x09, 0xb5,
	0xc5, 0x48, 0xad, 0xc4, 0xa1, 0x8a, 0x72, 0x49, 0x22, 0xc1, 0x21, 0x52, 0xb4, 0x3c, 0x00, 0x5a,
	0xdb, 0x63, 0x7b, 0x05, 0xde, 0x75, 0x76, 0xc7, 0x4a, 0xf2, 0x04, 0x79, 0x82, 0xbc, 0x6f, 0xc4,
	0x1a, 0x6c, 0x94, 0x0b, 0x5c, 0xac, 0xf9, 0x3d, 0xdf, 0x3f, 0x33, 0x9a, 0x59, 0xb2, 0x48, 0x25,
	0x66, 0x65, 0x18, 0x44, 0x3a, 0x9f, 0x27, 0xa5, 0x05, 0xa3, 0x43, 0x8d, 0x32, 0xb2, 0xf3, 0xc7,
	0x52, 0x46, 0xb3, 0x28, 0x13, 0x4a, 0xc1, 0x6e, 0x6e, 0x74, 0x89, 0x50, 0x7d, 0x83, 0xc2, 0x68,
	0xd4, 0xb4, 0xe3, 0xc4, 0xe8, 0xea, 0x22, 0xbb, 0x8c, 0x41, 0xa1, 0xc4, 0x97, 0x3a, 0xa8, 0x8a,
	0x8c, 0xae, 0x2f, 0x72, 0x5b, 0x99, 0x2a, 0x81, 0xa5, 0x81, 0x26, 0xaa, 0xfc, 0x93, 0x57, 0x9f,
	0x74, 0xf8, 0x7e, 0x0e, 0xfa, 0x8b, 0xf8, 0x99, 0x2e, 0x98, 0x37, 0xf6, 0xa7, 0xbd, 0xbf, 0x2c,
	0x68, 0xc0, 0xb5, 0x4c, 0x15, 0xc4, 0xf7, 0x60, 0xad, 0x48, 0x81, 0xef, 0x21, 0xfa, 0x9f, 0xf4,
	0x62, 0xb0, 0x28, 0x95, 0x40, 0xa9, 0x15, 0x6b, 0x8d, 0x3d, 0xe7, 0xa9, 0x67, 0x7b, 0x00, 0x30,
	0x2b, 0x27, 0x12, 0x09, 0x86, 0x9f, 0xc2, 0xa3, 0xb7, 0x16, 0xf1, 0x97, 0xba, 0xa0, 0x01, 0xf9,
	0x74, 0xe4, 0x99, 0xe7, 0x0a, 0xd0, 0xa6, 0xc0, 0xea, 0x10, 0xf0, 0x9a, 0xa1, 0x33, 0x42, 0x43,
	0x11, 0x6d, 0x9f, 0x84, 0x89, 0x37, 0x52, 0x21, 0x98, 0x44, 0x44, 0xe0, 0x5a, 0x7f, 0xe1, 0xc3,
	0x63, 0x66, 0x75, 0x4c, 0xd0, 0xdf, 0x64, 0x98, 0x68, 0xf3, 0x81, 0xf6, 0x1d, 0x3d, 0x38, 0x24,
	0x1a, 0xf8, 0x27, 0xf9, 0x8c, 0x32, 0x07, 0x8b, 0x22, 0x2f, 0x58, 0x7b, 0xec, 0x4d, 0xdb, 0xbc,
	0xf9, 0x41, 0x17, 0xa4, 0x6f, 0x21, 0xcd, 0x41, 0xe1, 0x26, 0x13, 0x36, 0x63, 0x1d, 0x37, 0xed,
	0xf7, 0x93, 0x15, 0xdd, 0x0a, 0x14, 0x4b, 0x61, 0x33, 0xde, 0x3b, 0x80, 0x7b, 0x41, 0xff, 0x90,
	0xb6, 0x82, 0x67, 0x64, 0xdd, 0x33, 0xeb, 0x71, 0xd4, 0x64, 0x4b, 0xbe, 0xba, 0x43, 0xdc, 0x59,
	0x14, 0xe1, 0x4e, 0xda, 0x8c, 0xfe, 0x20, 0xd5, 0x13, 0x71, 0xeb, 0xe9, 0xf3, 0x4a, 0xd0, 0x1b,
	0x32, 0x70, 0xc1, 0xa6, 0x6e, 0x6f, 0x59, 0xeb, 0xcc, 0xd1, 0xbe, 0x39, 0xc7, 0xba, 0x36, 0x84,
	0x5d, 0x77, 0xfd, 0x7f, 0xef, 0x01, 0x00, 0x00, 0xff, 0xff, 0x6f, 0x2d, 0x8a, 0x94, 0xbc, 0x02,
	0x00, 0x00,
}
