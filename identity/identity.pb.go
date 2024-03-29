// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/fuserobotics/quic-channel/identity/identity.proto

/*
Package identity is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/identity/identity.proto

It has these top-level messages:
	Identity
	PeerIdentifier
	PeerConnection
*/
package identity

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

// Identity contains just enough information to identify a peer.
type Identity struct {
	// CertAsn1 contains each certificate in the chain, with the first certificate as the leaf.
	CertAsn1 [][]byte `protobuf:"bytes,1,rep,name=cert_asn1,json=certAsn1,proto3" json:"cert_asn1,omitempty"`
}

func (m *Identity) Reset()                    { *m = Identity{} }
func (m *Identity) String() string            { return proto.CompactTextString(m) }
func (*Identity) ProtoMessage()               {}
func (*Identity) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Identity) GetCertAsn1() [][]byte {
	if m != nil {
		return m.CertAsn1
	}
	return nil
}

// PeerIdentifier is an encoded and potentially partial match against a peer public key.
type PeerIdentifier struct {
	// Match by public key hash. Partials are accepted, with a minimum length.
	MatchPublicKey []byte `protobuf:"bytes,1,opt,name=match_public_key,json=matchPublicKey,proto3" json:"match_public_key,omitempty"`
}

func (m *PeerIdentifier) Reset()                    { *m = PeerIdentifier{} }
func (m *PeerIdentifier) String() string            { return proto.CompactTextString(m) }
func (*PeerIdentifier) ProtoMessage()               {}
func (*PeerIdentifier) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *PeerIdentifier) GetMatchPublicKey() []byte {
	if m != nil {
		return m.MatchPublicKey
	}
	return nil
}

// PeerConnection contains connection info for a peer.
type PeerConnection struct {
	// Address is the addr:port to connect to.
	Address string `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
}

func (m *PeerConnection) Reset()                    { *m = PeerConnection{} }
func (m *PeerConnection) String() string            { return proto.CompactTextString(m) }
func (*PeerConnection) ProtoMessage()               {}
func (*PeerConnection) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PeerConnection) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func init() {
	proto.RegisterType((*Identity)(nil), "identity.Identity")
	proto.RegisterType((*PeerIdentifier)(nil), "identity.PeerIdentifier")
	proto.RegisterType((*PeerConnection)(nil), "identity.PeerConnection")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/identity/identity.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 199 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x3c, 0x8e, 0x31, 0x4b, 0xc4, 0x40,
	0x10, 0x46, 0x09, 0x82, 0xe6, 0x96, 0xe3, 0x90, 0xad, 0x02, 0x36, 0x47, 0x1a, 0x83, 0xe0, 0x85,
	0xc3, 0x4e, 0x6c, 0xc4, 0x4a, 0x6c, 0x8e, 0xfc, 0x81, 0xb0, 0x3b, 0x99, 0x98, 0xc1, 0x64, 0x36,
	0xee, 0xce, 0x16, 0xf9, 0xf7, 0xe2, 0xc6, 0xd8, 0x7d, 0xef, 0x31, 0x0f, 0x46, 0xbd, 0x7c, 0x92,
	0x0c, 0xd1, 0x9e, 0xc0, 0x4d, 0x75, 0x1f, 0x03, 0x7a, 0x67, 0x9d, 0x10, 0x84, 0xfa, 0x3b, 0x12,
	0x3c, 0xc2, 0x60, 0x98, 0x71, 0xac, 0xa9, 0x43, 0x16, 0x92, 0xe5, 0x7f, 0x9c, 0x66, 0xef, 0xc4,
	0xe9, 0x7c, 0xe3, 0xf2, 0x5e, 0xe5, 0xef, 0x7f, 0x5b, 0xdf, 0xa9, 0x1d, 0xa0, 0x97, 0xd6, 0x04,
	0x3e, 0x17, 0xd9, 0xf1, 0xaa, 0xda, 0x37, 0xf9, 0xaf, 0x78, 0x0d, 0x7c, 0x2e, 0x9f, 0xd5, 0xe1,
	0x82, 0xe8, 0xd7, 0xe3, 0x9e, 0xd0, 0xeb, 0x4a, 0xdd, 0x4e, 0x46, 0x60, 0x68, 0xe7, 0x68, 0x47,
	0x82, 0xf6, 0x0b, 0x97, 0x22, 0x3b, 0x66, 0xd5, 0xbe, 0x39, 0x24, 0x7f, 0x49, 0xfa, 0x03, 0x97,
	0xf2, 0x61, 0x6d, 0xdf, 0x1c, 0x33, 0x82, 0x90, 0x63, 0x5d, 0xa8, 0x1b, 0xd3, 0x75, 0x1e, 0x43,
	0x48, 0xc9, 0xae, 0xd9, 0xd0, 0x5e, 0xa7, 0x0f, 0x9f, 0x7e, 0x02, 0x00, 0x00, 0xff, 0xff, 0x42,
	0x88, 0x36, 0xaf, 0xe1, 0x00, 0x00, 0x00,
}
