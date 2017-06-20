// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/discovery/discovery.proto
// DO NOT EDIT!

/*
Package discovery is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/discovery/discovery.proto

It has these top-level messages:
	DiscoveryEvent
	DiscoveryUDPPacket
*/
package discovery

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
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

// DiscoveryEventKind are kinds of discovery events.
type DiscoveryEventKind int32

const (
	// When a UDP broadcast is observed over LAN
	DiscoveryEventKind_DISCOVER_OBSERVED_BROADCAST DiscoveryEventKind = 0
	// When the internet connection with this peer is established.
	DiscoveryEventKind_DISCOVER_INET_CONN_ESTABLISHED DiscoveryEventKind = 1
)

var DiscoveryEventKind_name = map[int32]string{
	0: "DISCOVER_OBSERVED_BROADCAST",
	1: "DISCOVER_INET_CONN_ESTABLISHED",
}
var DiscoveryEventKind_value = map[string]int32{
	"DISCOVER_OBSERVED_BROADCAST":    0,
	"DISCOVER_INET_CONN_ESTABLISHED": 1,
}

func (x DiscoveryEventKind) String() string {
	return proto.EnumName(DiscoveryEventKind_name, int32(x))
}
func (DiscoveryEventKind) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// DiscoveryEvent represents an observation of a peer over a network.
type DiscoveryEvent struct {
	// PeerId is the PublicKeyHash array.
	PeerId *identity.PeerIdentifier `protobuf:"bytes,1,opt,name=peer_id,json=peerId" json:"peer_id,omitempty"`
	// Timestamp is when the event was observed.
	Timestamp uint64 `protobuf:"varint,2,opt,name=timestamp" json:"timestamp,omitempty"`
	// Kind is the kind of discovery event.
	Kind DiscoveryEventKind `protobuf:"varint,3,opt,name=kind,enum=discovery.DiscoveryEventKind" json:"kind,omitempty"`
	// Inter is the observed interface.
	Inter uint32 `protobuf:"varint,4,opt,name=inter" json:"inter,omitempty"`
	// Extra info contains per-event-kind info.
	ExtraInfo []byte `protobuf:"bytes,5,opt,name=extra_info,json=extraInfo,proto3" json:"extra_info,omitempty"`
}

func (m *DiscoveryEvent) Reset()                    { *m = DiscoveryEvent{} }
func (m *DiscoveryEvent) String() string            { return proto.CompactTextString(m) }
func (*DiscoveryEvent) ProtoMessage()               {}
func (*DiscoveryEvent) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *DiscoveryEvent) GetPeerId() *identity.PeerIdentifier {
	if m != nil {
		return m.PeerId
	}
	return nil
}

func (m *DiscoveryEvent) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *DiscoveryEvent) GetKind() DiscoveryEventKind {
	if m != nil {
		return m.Kind
	}
	return DiscoveryEventKind_DISCOVER_OBSERVED_BROADCAST
}

func (m *DiscoveryEvent) GetInter() uint32 {
	if m != nil {
		return m.Inter
	}
	return 0
}

func (m *DiscoveryEvent) GetExtraInfo() []byte {
	if m != nil {
		return m.ExtraInfo
	}
	return nil
}

// DiscoveryUDPPacket is a UDP discovery packet.
type DiscoveryUDPPacket struct {
	Port uint32 `protobuf:"varint,1,opt,name=port" json:"port,omitempty"`
}

func (m *DiscoveryUDPPacket) Reset()                    { *m = DiscoveryUDPPacket{} }
func (m *DiscoveryUDPPacket) String() string            { return proto.CompactTextString(m) }
func (*DiscoveryUDPPacket) ProtoMessage()               {}
func (*DiscoveryUDPPacket) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *DiscoveryUDPPacket) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func init() {
	proto.RegisterType((*DiscoveryEvent)(nil), "discovery.DiscoveryEvent")
	proto.RegisterType((*DiscoveryUDPPacket)(nil), "discovery.DiscoveryUDPPacket")
	proto.RegisterEnum("discovery.DiscoveryEventKind", DiscoveryEventKind_name, DiscoveryEventKind_value)
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/discovery/discovery.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 332 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x90, 0x51, 0x4b, 0xeb, 0x30,
	0x1c, 0xc5, 0x6f, 0xee, 0xed, 0x76, 0x59, 0x74, 0x63, 0x04, 0x1f, 0x8a, 0x3a, 0x2d, 0x7b, 0x2a,
	0x82, 0x1d, 0x9b, 0xaf, 0x22, 0x6c, 0x6b, 0xc0, 0xa2, 0xac, 0x23, 0x9d, 0x03, 0x9f, 0x4a, 0xd7,
	0xfe, 0xeb, 0xc2, 0x5c, 0x52, 0xd3, 0x6c, 0xb8, 0x8f, 0xe8, 0xb7, 0x12, 0x32, 0xec, 0xf4, 0xcd,
	0xb7, 0x73, 0x0e, 0x27, 0xbf, 0x3f, 0x27, 0xf8, 0xee, 0x85, 0xeb, 0xe5, 0x66, 0xe1, 0xa5, 0x72,
	0xdd, 0xcb, 0x37, 0x25, 0x28, 0xb9, 0x90, 0x9a, 0xa7, 0x65, 0xef, 0x6d, 0xc3, 0xd3, 0xeb, 0x74,
	0x99, 0x08, 0x01, 0xaf, 0xbd, 0x8c, 0x97, 0xa9, 0xdc, 0x82, 0xda, 0x1d, 0x94, 0x57, 0x28, 0xa9,
	0x25, 0x69, 0x54, 0xc1, 0xe9, 0xed, 0xaf, 0x50, 0x3c, 0x03, 0xa1, 0xb9, 0xde, 0x55, 0x62, 0x0f,
	0xea, 0x7e, 0x20, 0xdc, 0xf2, 0xbf, 0x58, 0x74, 0x0b, 0x42, 0x93, 0x3e, 0xfe, 0x5f, 0x00, 0xa8,
	0x98, 0x67, 0x36, 0x72, 0x90, 0x7b, 0x34, 0xb0, 0xbd, 0xea, 0xd1, 0x14, 0x40, 0x05, 0xc6, 0xe4,
	0x1c, 0x14, 0xab, 0x17, 0xc6, 0x93, 0x73, 0xdc, 0xd0, 0x7c, 0x0d, 0xa5, 0x4e, 0xd6, 0x85, 0xfd,
	0xd7, 0x41, 0xae, 0xc5, 0x0e, 0x01, 0xe9, 0x63, 0x6b, 0xc5, 0x45, 0x66, 0xff, 0x73, 0x90, 0xdb,
	0x1a, 0x74, 0xbc, 0xc3, 0x98, 0x9f, 0x97, 0x1f, 0xb8, 0xc8, 0x98, 0xa9, 0x92, 0x13, 0x5c, 0xe3,
	0x42, 0x83, 0xb2, 0x2d, 0x07, 0xb9, 0x4d, 0xb6, 0x37, 0xa4, 0x83, 0x31, 0xbc, 0x6b, 0x95, 0xc4,
	0x5c, 0xe4, 0xd2, 0xae, 0x39, 0xc8, 0x3d, 0x66, 0x0d, 0x93, 0x04, 0x22, 0x97, 0x5d, 0x17, 0x93,
	0x0a, 0xf8, 0xe4, 0x4f, 0xa7, 0x49, 0xba, 0x02, 0x4d, 0x08, 0xb6, 0x0a, 0xa9, 0xb4, 0xd9, 0xd2,
	0x64, 0x46, 0x5f, 0x3d, 0x7f, 0x6b, 0x56, 0xa7, 0xc9, 0x25, 0x3e, 0xf3, 0x83, 0x68, 0x1c, 0xce,
	0x29, 0x8b, 0xc3, 0x51, 0x44, 0xd9, 0x9c, 0xfa, 0xf1, 0x88, 0x85, 0x43, 0x7f, 0x3c, 0x8c, 0x66,
	0xed, 0x3f, 0xa4, 0x8b, 0x2f, 0xaa, 0x42, 0x30, 0xa1, 0xb3, 0x78, 0x1c, 0x4e, 0x26, 0x31, 0x8d,
	0x66, 0xc3, 0xd1, 0x63, 0x10, 0xdd, 0x53, 0xbf, 0x8d, 0x16, 0x75, 0xf3, 0xaf, 0x37, 0x9f, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x8a, 0x16, 0xd1, 0xeb, 0xe2, 0x01, 0x00, 0x00,
}
