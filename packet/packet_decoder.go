package packet

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/golang/protobuf/proto"
)

// PacketIdentifierFunc identifies packets by ID, returning a message instance or error.
type PacketIdentifierFunc func(packetType uint32) (Packet, error)

// packetHeaderLen is the length of the fixed-size header.
var packetHeaderLen = proto.Size(&PacketHeader{PacketLength: 1, PacketType: 1})

// PacketReadWriter reads and writes packets.
type PacketReadWriter struct {
	io.ReadWriter

	writeMtx  sync.Mutex
	header    PacketHeader
	headerBuf []byte
	bodyBuf   *bytes.Buffer
}

// NewPacketReaderWriter builds a new PacketReaderWriter.
func NewPacketReadWriter(rw io.ReadWriter) *PacketReadWriter {
	return &PacketReadWriter{
		ReadWriter: rw,
		headerBuf:  make([]byte, packetHeaderLen),
		bodyBuf:    &bytes.Buffer{},
	}
}

// ReadPacket reads a header and body from the stream.
func (r *PacketReadWriter) ReadPacket(identifier PacketIdentifierFunc) (Packet, error) {
	defer r.header.Reset()
	defer r.bodyBuf.Reset()

	// Read the packet header
	_, err := io.ReadFull(r, r.headerBuf)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(r.headerBuf, &r.header); err != nil {
		return nil, err
	}
	pktLen := int64(r.header.PacketLength) - 1
	if pktLen > int64(PacketMaxLength) {
		return nil, fmt.Errorf("Invalid packet len: %d", pktLen)
	}

	// Identify the message
	body, err := identifier(r.header.PacketType)
	if err != nil {
		return nil, err
	}

	// Read the body of the message
	if pktLen > 0 {
		_, err = io.CopyN(r.bodyBuf, r, pktLen)
		if err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(r.bodyBuf.Bytes(), body); err != nil {
			return nil, err
		}
	} else {
		// If the length is 0, all values are defaults.
		body.Reset()
	}

	return body, nil
}

// WritePacket writes a packet to the stream.
func (r *PacketReadWriter) WritePacket(packet Packet) error {
	body, err := proto.Marshal(packet)
	if err != nil {
		return err
	}
	if uint32(len(body)) > PacketMaxLength {
		return fmt.Errorf("Control packet is too large (%d > %d)", len(body), PacketMaxLength)
	}

	headerMsg := &PacketHeader{
		PacketLength: uint32(len(body)) + 1,
		PacketType:   packet.PacketType(),
	}

	header, err := proto.Marshal(headerMsg)
	if err != nil {
		return err
	}

	r.writeMtx.Lock()
	defer r.writeMtx.Unlock()

	_, err = r.Write(header)
	if err != nil {
		return err
	}

	_, err = r.Write(body)
	return err
}
