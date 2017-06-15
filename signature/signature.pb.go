// Code generated by protoc-gen-go.
// source: github.com/fuserobotics/quic-channel/signature/signature.proto
// DO NOT EDIT!

/*
Package signature is a generated protocol buffer package.

It is generated from these files:
	github.com/fuserobotics/quic-channel/signature/signature.proto

It has these top-level messages:
	SignedMessage
*/
package signature

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

type ESignedMessageHash int32

const (
	ESignedMessageHash_HASH_SHA256 ESignedMessageHash = 0
)

var ESignedMessageHash_name = map[int32]string{
	0: "HASH_SHA256",
}
var ESignedMessageHash_value = map[string]int32{
	"HASH_SHA256": 0,
}

func (x ESignedMessageHash) String() string {
	return proto.EnumName(ESignedMessageHash_name, int32(x))
}
func (ESignedMessageHash) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// SignedMessage is a signed protobuf message.
type SignedMessage struct {
	Message       []byte             `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	SignatureSalt []byte             `protobuf:"bytes,2,opt,name=signature_salt,json=signatureSalt,proto3" json:"signature_salt,omitempty"`
	Signature     []byte             `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
	HashType      ESignedMessageHash `protobuf:"varint,4,opt,name=hash_type,json=hashType,enum=signature.ESignedMessageHash" json:"hash_type,omitempty"`
}

func (m *SignedMessage) Reset()                    { *m = SignedMessage{} }
func (m *SignedMessage) String() string            { return proto.CompactTextString(m) }
func (*SignedMessage) ProtoMessage()               {}
func (*SignedMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *SignedMessage) GetMessage() []byte {
	if m != nil {
		return m.Message
	}
	return nil
}

func (m *SignedMessage) GetSignatureSalt() []byte {
	if m != nil {
		return m.SignatureSalt
	}
	return nil
}

func (m *SignedMessage) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *SignedMessage) GetHashType() ESignedMessageHash {
	if m != nil {
		return m.HashType
	}
	return ESignedMessageHash_HASH_SHA256
}

func init() {
	proto.RegisterType((*SignedMessage)(nil), "signature.SignedMessage")
	proto.RegisterEnum("signature.ESignedMessageHash", ESignedMessageHash_name, ESignedMessageHash_value)
}

func init() {
	proto.RegisterFile("github.com/fuserobotics/quic-channel/signature/signature.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 218 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xb2, 0x4b, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x2b, 0x2d, 0x4e, 0x2d, 0xca, 0x4f, 0xca, 0x2f,
	0xc9, 0x4c, 0x2e, 0xd6, 0x2f, 0x2c, 0xcd, 0x4c, 0xd6, 0x4d, 0xce, 0x48, 0xcc, 0xcb, 0x4b, 0xcd,
	0xd1, 0x2f, 0xce, 0x4c, 0xcf, 0x4b, 0x2c, 0x29, 0x2d, 0x4a, 0x45, 0xb0, 0xf4, 0x0a, 0x8a, 0xf2,
	0x4b, 0xf2, 0x85, 0x38, 0xe1, 0x02, 0x4a, 0xab, 0x18, 0xb9, 0x78, 0x83, 0x33, 0xd3, 0xf3, 0x52,
	0x53, 0x7c, 0x53, 0x8b, 0x8b, 0x13, 0xd3, 0x53, 0x85, 0x24, 0xb8, 0xd8, 0x73, 0x21, 0x4c, 0x09,
	0x46, 0x05, 0x46, 0x0d, 0x9e, 0x20, 0x18, 0x57, 0x48, 0x95, 0x8b, 0x0f, 0xae, 0x31, 0xbe, 0x38,
	0x31, 0xa7, 0x44, 0x82, 0x09, 0xac, 0x80, 0x17, 0x2e, 0x1a, 0x9c, 0x98, 0x53, 0x22, 0x24, 0xc3,
	0x85, 0x30, 0x5f, 0x82, 0x19, 0xac, 0x02, 0x21, 0x20, 0x64, 0xc5, 0xc5, 0x99, 0x91, 0x58, 0x9c,
	0x11, 0x5f, 0x52, 0x59, 0x90, 0x2a, 0xc1, 0xa2, 0xc0, 0xa8, 0xc1, 0x67, 0x24, 0xab, 0x87, 0x70,
	0xa0, 0x2b, 0x8a, 0x63, 0x3c, 0x12, 0x8b, 0x33, 0x82, 0x38, 0x40, 0xea, 0x43, 0x2a, 0x0b, 0x52,
	0xb5, 0x54, 0xb9, 0x84, 0x30, 0xe5, 0x85, 0xf8, 0xb9, 0xb8, 0x3d, 0x1c, 0x83, 0x3d, 0xe2, 0x83,
	0x3d, 0x1c, 0x8d, 0x4c, 0xcd, 0x04, 0x18, 0x92, 0xd8, 0xc0, 0xbe, 0x34, 0x06, 0x04, 0x00, 0x00,
	0xff, 0xff, 0xae, 0x84, 0xd5, 0x56, 0x27, 0x01, 0x00, 0x00,
}
