// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/fuserobotics/quic-channel/handshake/handshake.proto

/*
Package handshake is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/handshake/handshake.proto

It has these top-level messages:
	SessionInitChallenge
	SessionInitResponse
	SessionChallenge
	SessionChallengeResponse
*/
package handshake

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

// SessionInitChallenge challenges the client with a salt.
type SessionInitChallenge struct {
	// Timestamp is the time the server began the session.
	// In case of a dispute, the oldest session will be kept.
	Timestamp uint64 `protobuf:"varint,1,opt,name=timestamp" json:"timestamp,omitempty"`
	// Challenge is the session challenge data.
	Challenge *SessionChallenge `protobuf:"bytes,2,opt,name=challenge" json:"challenge,omitempty"`
}

func (m *SessionInitChallenge) Reset()                    { *m = SessionInitChallenge{} }
func (m *SessionInitChallenge) String() string            { return proto.CompactTextString(m) }
func (*SessionInitChallenge) ProtoMessage()               {}
func (*SessionInitChallenge) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *SessionInitChallenge) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *SessionInitChallenge) GetChallenge() *SessionChallenge {
	if m != nil {
		return m.Challenge
	}
	return nil
}

// SessionInitResponse responds to the SessionInitChallenge.
type SessionInitResponse struct {
	// Signature is the signed SessionChallengeResponse, usually with a salt.
	Signature *signature.SignedMessage `protobuf:"bytes,1,opt,name=signature" json:"signature,omitempty"`
	// Challenge is the second challenge step, if step 2
	Challenge *SessionChallenge `protobuf:"bytes,2,opt,name=challenge" json:"challenge,omitempty"`
}

func (m *SessionInitResponse) Reset()                    { *m = SessionInitResponse{} }
func (m *SessionInitResponse) String() string            { return proto.CompactTextString(m) }
func (*SessionInitResponse) ProtoMessage()               {}
func (*SessionInitResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *SessionInitResponse) GetSignature() *signature.SignedMessage {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *SessionInitResponse) GetChallenge() *SessionChallenge {
	if m != nil {
		return m.Challenge
	}
	return nil
}

// SessionChallenge is the message the server asks the client to sign.
type SessionChallenge struct {
	// ChallengeNonce is a random bit string for the challenge.
	ChallengeNonce []byte `protobuf:"bytes,1,opt,name=challenge_nonce,json=challengeNonce,proto3" json:"challenge_nonce,omitempty"`
}

func (m *SessionChallenge) Reset()                    { *m = SessionChallenge{} }
func (m *SessionChallenge) String() string            { return proto.CompactTextString(m) }
func (*SessionChallenge) ProtoMessage()               {}
func (*SessionChallenge) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *SessionChallenge) GetChallengeNonce() []byte {
	if m != nil {
		return m.ChallengeNonce
	}
	return nil
}

// SessionChallengeResponse is the signed challenge response.
type SessionChallengeResponse struct {
	// Challenge is the challenge we are responding to repeated again.
	Challenge *SessionChallenge `protobuf:"bytes,1,opt,name=challenge" json:"challenge,omitempty"`
	// Identity is the identity of the peer.
	Identity *identity.Identity `protobuf:"bytes,2,opt,name=identity" json:"identity,omitempty"`
}

func (m *SessionChallengeResponse) Reset()                    { *m = SessionChallengeResponse{} }
func (m *SessionChallengeResponse) String() string            { return proto.CompactTextString(m) }
func (*SessionChallengeResponse) ProtoMessage()               {}
func (*SessionChallengeResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *SessionChallengeResponse) GetChallenge() *SessionChallenge {
	if m != nil {
		return m.Challenge
	}
	return nil
}

func (m *SessionChallengeResponse) GetIdentity() *identity.Identity {
	if m != nil {
		return m.Identity
	}
	return nil
}

func init() {
	proto.RegisterType((*SessionInitChallenge)(nil), "handshake.SessionInitChallenge")
	proto.RegisterType((*SessionInitResponse)(nil), "handshake.SessionInitResponse")
	proto.RegisterType((*SessionChallenge)(nil), "handshake.SessionChallenge")
	proto.RegisterType((*SessionChallengeResponse)(nil), "handshake.SessionChallengeResponse")
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/handshake/handshake.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 293 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x91, 0xcf, 0x4a, 0xf4, 0x30,
	0x14, 0xc5, 0xc9, 0xc7, 0x87, 0xd8, 0x8c, 0xa8, 0x44, 0x17, 0x65, 0x74, 0x31, 0xcc, 0xc6, 0xd9,
	0x98, 0x81, 0x11, 0x04, 0x51, 0xdc, 0xb8, 0x9a, 0x85, 0x2e, 0x3a, 0x0f, 0x20, 0x69, 0x7a, 0x6d,
	0x83, 0xed, 0x4d, 0xed, 0x4d, 0x17, 0x3e, 0x80, 0xe0, 0x63, 0xcb, 0x4c, 0xdb, 0xc4, 0x3f, 0x9b,
	0x11, 0x77, 0x87, 0x93, 0x93, 0x73, 0x7f, 0x97, 0xcb, 0x6f, 0x73, 0xe3, 0x8a, 0x36, 0x95, 0xda,
	0x56, 0xf3, 0xa7, 0x96, 0xa0, 0xb1, 0xa9, 0x75, 0x46, 0xd3, 0xfc, 0xa5, 0x35, 0xfa, 0x5c, 0x17,
	0x0a, 0x11, 0xca, 0x79, 0xa1, 0x30, 0xa3, 0x42, 0x3d, 0x43, 0x50, 0xb2, 0x6e, 0xac, 0xb3, 0x22,
	0xf2, 0xc6, 0xf8, 0x66, 0xab, 0x2a, 0x93, 0x01, 0x3a, 0xe3, 0x5e, 0xbd, 0xe8, 0x8a, 0xc6, 0xdb,
	0x81, 0x90, 0xc9, 0x51, 0xb9, 0xb6, 0x81, 0xa0, 0xba, 0xff, 0x53, 0xcb, 0x8f, 0x57, 0x40, 0x64,
	0x2c, 0x2e, 0xd1, 0xb8, 0xbb, 0x42, 0x95, 0x25, 0x60, 0x0e, 0xe2, 0x94, 0x47, 0xce, 0x54, 0x40,
	0x4e, 0x55, 0x75, 0xcc, 0x26, 0x6c, 0xf6, 0x3f, 0x09, 0x86, 0xb8, 0xe2, 0x91, 0x1e, 0xa2, 0xf1,
	0xbf, 0x09, 0x9b, 0x8d, 0x16, 0x27, 0x32, 0xec, 0xd8, 0x37, 0xfa, 0xb6, 0x24, 0xa4, 0xa7, 0xef,
	0x8c, 0x1f, 0x7d, 0x9a, 0x98, 0x00, 0xd5, 0x16, 0x09, 0xc4, 0x25, 0x8f, 0x3c, 0xdb, 0x66, 0xe0,
	0x68, 0x11, 0xcb, 0x40, 0xbb, 0x32, 0x39, 0x42, 0x76, 0x0f, 0x44, 0x6a, 0xdd, 0xe7, 0x1f, 0xfe,
	0x82, 0x72, 0xcd, 0x0f, 0xbf, 0x3f, 0x8b, 0x33, 0x7e, 0xe0, 0x03, 0x8f, 0x68, 0x51, 0x77, 0x30,
	0x7b, 0xc9, 0xbe, 0xb7, 0x1f, 0xd6, 0xee, 0xf4, 0x8d, 0xf1, 0xf8, 0x47, 0xf9, 0xb0, 0xcc, 0x17,
	0x28, 0xf6, 0x1b, 0x28, 0x21, 0xf9, 0xee, 0x70, 0xe2, 0x7e, 0x1d, 0x21, 0xfd, 0xcd, 0x97, 0xbd,
	0x48, 0x7c, 0x26, 0xdd, 0xd9, 0xdc, 0xf1, 0xe2, 0x23, 0x00, 0x00, 0xff, 0xff, 0x3a, 0x33, 0x53,
	0x89, 0x92, 0x02, 0x00, 0x00,
}
