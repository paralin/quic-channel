// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/circuit/circuit.proto
// DO NOT EDIT!

/*
Package circuit is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/circuit/circuit.proto
	github.com/fuserobotics/quic-channel/circuit/control.proto

It has these top-level messages:
	CircuitProbe
	CircuitPeerLookupRequest
	CircuitPeerLookupResponse
	CircuitInit
	CircuitPacket
	CircuitEstablished
	SessionInitChallenge
	SessionInitResponse
	SessionChallenge
	SessionChallengeResponse
	KeepAlive
*/
package circuit

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import route "github.com/fuserobotics/quic-channel/route"
import identity "github.com/fuserobotics/quic-channel/identity"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// EStreamType are the types of Circuit streams.
type EStreamType int32

const (
	// Control stream, used for control messages.
	EStreamType_STREAM_CONTROL EStreamType = 0
	// Circuit stream, used for building circuits.
	EStreamType_STREAM_CIRCUIT EStreamType = 1
)

var EStreamType_name = map[int32]string{
	0: "STREAM_CONTROL",
	1: "STREAM_CIRCUIT",
}
var EStreamType_value = map[string]int32{
	"STREAM_CONTROL": 0,
	"STREAM_CIRCUIT": 1,
}

func (x EStreamType) String() string {
	return proto.EnumName(EStreamType_name, int32(x))
}
func (EStreamType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// CircuitProbe is a probe to build a circuit.
// control packet_type: 5
type CircuitProbe struct {
	// Route contains the route so far.
	Route *route.Route `protobuf:"bytes,1,opt,name=route" json:"route,omitempty"`
}

func (m *CircuitProbe) Reset()                    { *m = CircuitProbe{} }
func (m *CircuitProbe) String() string            { return proto.CompactTextString(m) }
func (*CircuitProbe) ProtoMessage()               {}
func (*CircuitProbe) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *CircuitProbe) GetRoute() *route.Route {
	if m != nil {
		return m.Route
	}
	return nil
}

// CircuitPeerLookupRequest is a request for peer ids given in the last route probe.
// control+circuit packet_type: 6
type CircuitPeerLookupRequest struct {
	// QueryNonce is an identifier for the request.
	QueryNonce uint32 `protobuf:"varint,1,opt,name=query_nonce,json=queryNonce" json:"query_nonce,omitempty"`
	// RequestedPeer are the peers in the list.
	RequestedPeer []*identity.PeerIdentifier `protobuf:"bytes,2,rep,name=requested_peer,json=requestedPeer" json:"requested_peer,omitempty"`
}

func (m *CircuitPeerLookupRequest) Reset()                    { *m = CircuitPeerLookupRequest{} }
func (m *CircuitPeerLookupRequest) String() string            { return proto.CompactTextString(m) }
func (*CircuitPeerLookupRequest) ProtoMessage()               {}
func (*CircuitPeerLookupRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *CircuitPeerLookupRequest) GetQueryNonce() uint32 {
	if m != nil {
		return m.QueryNonce
	}
	return 0
}

func (m *CircuitPeerLookupRequest) GetRequestedPeer() []*identity.PeerIdentifier {
	if m != nil {
		return m.RequestedPeer
	}
	return nil
}

// CircuitPeerLookupResponse is a response with peer identities.
// control+circuit packet_type: 7
type CircuitPeerLookupResponse struct {
	// QueryNonce is an identifier for the request.
	QueryNonce uint32 `protobuf:"varint,1,opt,name=query_nonce,json=queryNonce" json:"query_nonce,omitempty"`
	// RequestedPeer are the peers in the list.
	RequestedPeer []*identity.Identity `protobuf:"bytes,2,rep,name=requested_peer,json=requestedPeer" json:"requested_peer,omitempty"`
}

func (m *CircuitPeerLookupResponse) Reset()                    { *m = CircuitPeerLookupResponse{} }
func (m *CircuitPeerLookupResponse) String() string            { return proto.CompactTextString(m) }
func (*CircuitPeerLookupResponse) ProtoMessage()               {}
func (*CircuitPeerLookupResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *CircuitPeerLookupResponse) GetQueryNonce() uint32 {
	if m != nil {
		return m.QueryNonce
	}
	return 0
}

func (m *CircuitPeerLookupResponse) GetRequestedPeer() []*identity.Identity {
	if m != nil {
		return m.RequestedPeer
	}
	return nil
}

// CircuitInit is the first message on the circuit stream.
// circuit packet_type: 1
type CircuitInit struct {
	// RouteEstablish is the route establish chain.
	RouteEstablish *route.RouteEstablish `protobuf:"bytes,1,opt,name=route_establish,json=routeEstablish" json:"route_establish,omitempty"`
}

func (m *CircuitInit) Reset()                    { *m = CircuitInit{} }
func (m *CircuitInit) String() string            { return proto.CompactTextString(m) }
func (*CircuitInit) ProtoMessage()               {}
func (*CircuitInit) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *CircuitInit) GetRouteEstablish() *route.RouteEstablish {
	if m != nil {
		return m.RouteEstablish
	}
	return nil
}

// CircuitPacket is a packet sent over the circuit.
// circuit packet_type 2
type CircuitPacket struct {
	// PacketData is the data in the packet.
	PacketData []byte `protobuf:"bytes,1,opt,name=packet_data,json=packetData,proto3" json:"packet_data,omitempty"`
}

func (m *CircuitPacket) Reset()                    { *m = CircuitPacket{} }
func (m *CircuitPacket) String() string            { return proto.CompactTextString(m) }
func (*CircuitPacket) ProtoMessage()               {}
func (*CircuitPacket) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *CircuitPacket) GetPacketData() []byte {
	if m != nil {
		return m.PacketData
	}
	return nil
}

// CircuitEstablished is the ack that the circuit was successfully established.
// circuit packet_type 3
type CircuitEstablished struct {
	// FinalRouteEstablish contains the final signed route if necessary.
	FinalRouteEstablish *route.RouteEstablish `protobuf:"bytes,1,opt,name=final_route_establish,json=finalRouteEstablish" json:"final_route_establish,omitempty"`
}

func (m *CircuitEstablished) Reset()                    { *m = CircuitEstablished{} }
func (m *CircuitEstablished) String() string            { return proto.CompactTextString(m) }
func (*CircuitEstablished) ProtoMessage()               {}
func (*CircuitEstablished) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *CircuitEstablished) GetFinalRouteEstablish() *route.RouteEstablish {
	if m != nil {
		return m.FinalRouteEstablish
	}
	return nil
}

func init() {
	proto.RegisterType((*CircuitProbe)(nil), "circuit.CircuitProbe")
	proto.RegisterType((*CircuitPeerLookupRequest)(nil), "circuit.CircuitPeerLookupRequest")
	proto.RegisterType((*CircuitPeerLookupResponse)(nil), "circuit.CircuitPeerLookupResponse")
	proto.RegisterType((*CircuitInit)(nil), "circuit.CircuitInit")
	proto.RegisterType((*CircuitPacket)(nil), "circuit.CircuitPacket")
	proto.RegisterType((*CircuitEstablished)(nil), "circuit.CircuitEstablished")
	proto.RegisterEnum("circuit.EStreamType", EStreamType_name, EStreamType_value)
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/circuit/circuit.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 383 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x94, 0x52, 0x51, 0xab, 0xd3, 0x30,
	0x14, 0x76, 0x8a, 0x0a, 0xa7, 0xdb, 0xbc, 0x44, 0x2e, 0xd4, 0xfb, 0xe2, 0xa5, 0x4f, 0x17, 0xc1,
	0x4e, 0x26, 0x0a, 0x8a, 0x28, 0x32, 0xf7, 0x50, 0xb8, 0xdb, 0x24, 0xab, 0xcf, 0x25, 0x4d, 0xcf,
	0x5c, 0xd8, 0x96, 0x74, 0x69, 0x82, 0x0c, 0xfc, 0xf1, 0xd2, 0xa4, 0xad, 0x9b, 0x28, 0xee, 0xbe,
	0xa4, 0xe7, 0x7c, 0x27, 0xdf, 0xf7, 0x9d, 0x7e, 0x04, 0xde, 0x7f, 0x17, 0x66, 0x6d, 0xf3, 0x98,
	0xab, 0xdd, 0x68, 0x65, 0x2b, 0xd4, 0x2a, 0x57, 0x46, 0xf0, 0x6a, 0xb4, 0xb7, 0x82, 0xbf, 0xe4,
	0x6b, 0x26, 0x25, 0x6e, 0x47, 0x5c, 0x68, 0x6e, 0x85, 0x69, 0xbf, 0x71, 0xa9, 0x95, 0x51, 0xe4,
	0x71, 0xd3, 0x5e, 0xbd, 0x3d, 0x4b, 0x44, 0x2b, 0x6b, 0xd0, 0x9f, 0x5e, 0xe0, 0xea, 0xc3, 0x59,
	0x3c, 0x51, 0xa0, 0x34, 0xc2, 0x1c, 0xba, 0xc2, 0xb3, 0xa3, 0x31, 0xf4, 0x27, 0x7e, 0x81, 0xaf,
	0x5a, 0xe5, 0x48, 0x22, 0x78, 0xe8, 0xc4, 0xc3, 0xde, 0x75, 0xef, 0x26, 0x18, 0xf7, 0x63, 0x6f,
	0x45, 0xeb, 0x93, 0xfa, 0x51, 0xf4, 0x13, 0xc2, 0x96, 0x83, 0xa8, 0x6f, 0x95, 0xda, 0xd8, 0x92,
	0xe2, 0xde, 0x62, 0x65, 0xc8, 0x73, 0x08, 0xf6, 0x16, 0xf5, 0x21, 0x93, 0x4a, 0x72, 0xaf, 0x32,
	0xa0, 0xe0, 0xa0, 0x79, 0x8d, 0x90, 0x4f, 0x30, 0xd4, 0xfe, 0x2e, 0x16, 0x59, 0x89, 0xa8, 0xc3,
	0xfb, 0xd7, 0x0f, 0x6e, 0x82, 0x71, 0x18, 0x77, 0x9b, 0xd5, 0xaa, 0x89, 0x6b, 0x56, 0x02, 0x35,
	0x1d, 0x74, 0xf7, 0xeb, 0x41, 0xf4, 0x03, 0x9e, 0xfd, 0xc5, 0xbd, 0x2a, 0x95, 0xac, 0xf0, 0xff,
	0xf6, 0xef, 0xfe, 0x61, 0x4f, 0x7e, 0xdb, 0x27, 0x4d, 0xf1, 0xa7, 0xf1, 0x0c, 0x82, 0xc6, 0x38,
	0x91, 0xc2, 0x90, 0x8f, 0xf0, 0xc4, 0xc5, 0x91, 0x61, 0x65, 0x58, 0xbe, 0x15, 0xd5, 0xba, 0xc9,
	0xec, 0xf2, 0x38, 0xb3, 0x69, 0x3b, 0xa4, 0x43, 0x7d, 0xd2, 0x47, 0xaf, 0x60, 0xd0, 0xfe, 0x07,
	0xe3, 0x1b, 0x74, 0xd1, 0x95, 0xae, 0xca, 0x0a, 0x66, 0x98, 0x13, 0xeb, 0x53, 0xf0, 0xd0, 0x17,
	0x66, 0x58, 0x94, 0x01, 0x69, 0x18, 0x9d, 0x0a, 0x16, 0x24, 0x81, 0xcb, 0x95, 0x90, 0x6c, 0x9b,
	0xdd, 0x69, 0x9b, 0xa7, 0x8e, 0x73, 0x0a, 0xbe, 0x78, 0x03, 0xc1, 0x74, 0x69, 0x34, 0xb2, 0x5d,
	0x7a, 0x28, 0x91, 0x10, 0x18, 0x2e, 0x53, 0x3a, 0xfd, 0x3c, 0xcb, 0x26, 0x8b, 0x79, 0x4a, 0x17,
	0xb7, 0x17, 0xf7, 0x8e, 0xb1, 0x84, 0x4e, 0xbe, 0x25, 0xe9, 0x45, 0x2f, 0x7f, 0xe4, 0x9e, 0xd2,
	0xeb, 0x5f, 0x01, 0x00, 0x00, 0xff, 0xff, 0xe8, 0x06, 0x73, 0x88, 0x07, 0x03, 0x00, 0x00,
}
