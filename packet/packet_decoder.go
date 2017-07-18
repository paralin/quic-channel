package packet

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/fuserobotics/quic-channel/memory"
	"github.com/golang/protobuf/proto"
)

// packetHeaderLen is the length of the fixed-size header.
var packetHeaderLen = proto.Size(&PacketHeader{PacketLength: 1, PacketType: 1})

// PacketReadWriter reads and writes packets.
type PacketReadWriter struct {
	io.ReadWriter

	writeMtx  sync.Mutex
	header    PacketHeader
	headerBuf []byte
	bodyArena *memory.BufferArena
}

// NewPacketReaderWriter builds a new PacketReaderWriter.
func NewPacketReadWriter(rw io.ReadWriter) *PacketReadWriter {
	return &PacketReadWriter{
		ReadWriter: rw,
		headerBuf:  make([]byte, packetHeaderLen),
		bodyArena:  memory.NewBufferArena(10),
	}
}

// FeedBuffer returns a buffer to the reader for later use.
func (r *PacketReadWriter) FeedBuffer(buf *bytes.Buffer) {
	r.bodyArena.PutBuffer(buf)
}

// ReadPacket reads a header and body from the stream.
// Note: while writing is thread-safe, reading is not.
func (r *PacketReadWriter) ReadPacket(identifier PacketIdentifierFunc) (Packet, PacketType, error) {
	defer r.header.Reset()

	// Read the packet header
	_, err := io.ReadFull(r, r.headerBuf)
	if err != nil {
		return nil, 0, err
	}
	if err := proto.Unmarshal(r.headerBuf, &r.header); err != nil {
		return nil, 0, err
	}
	pktLen := int64(r.header.PacketLength) - 1
	if pktLen > int64(PacketMaxLength) {
		return nil, 0, fmt.Errorf("Invalid packet len: %d", pktLen)
	}

	// Identify the message
	packetType := PacketType(r.header.PacketType)
	body, err := identifier(packetType)
	if err != nil {
		return nil, packetType, err
	}

	// Read the body of the message
	bodyBuf := r.bodyArena.GetBuffer()
	if pktLen > 0 {
		_, err = io.CopyN(bodyBuf, r, pktLen)
		if err != nil {
			return nil, packetType, err
		}

		if body == nil {
			return NewRawPacket(packetType, bodyBuf), packetType, nil
		}

		if err := proto.Unmarshal(bodyBuf.Bytes(), body); err != nil {
			return nil, packetType, err
		}
	} else {
		if body == nil {
			bodyBuf.Reset()
			return NewRawPacket(packetType, bodyBuf), packetType, nil
		}

		// If the length is 0, all values are defaults.
		body.Reset()
	}

	return body, packetType, nil
}

// WriteRawPacket writes a raw packet to the stream.
func (r *PacketReadWriter) WriteRawPacket(packetType PacketType, packet *bytes.Buffer) error {
	if uint32(packet.Len()) > PacketMaxLength {
		return fmt.Errorf(
			"packet is too large (%d > %d)",
			packet.Len(),
			PacketMaxLength,
		)
	}

	headerMsg := &PacketHeader{
		PacketLength: uint32(packet.Len()) + 1,
		PacketType:   uint32(packetType),
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

	_, err = packet.WriteTo(r)
	return err
}

// WritePacket writes a packet to the stream.
func (r *PacketReadWriter) WriteProtoPacket(packet ProtoPacket) error {
	body, err := proto.Marshal(packet)
	if err != nil {
		return err
	}
	if uint32(len(body)) > PacketMaxLength {
		return fmt.Errorf("packet is too large (%d > %d)", len(body), PacketMaxLength)
	}

	headerMsg := &PacketHeader{
		PacketLength: uint32(len(body)) + 1,
		PacketType:   uint32(packet.GetPacketType()),
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
