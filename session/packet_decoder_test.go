package session

import (
	"bytes"
	"fmt"
	"testing"
)

// TestPacketE2E tests encode/decode of a packet.
func TestPacketE2E(t *testing.T) {
	rw := NewPacketReadWriter(&bytes.Buffer{})
	pkt := &StreamInit{StreamType: EStreamType_STREAM_CONTROL}
	if err := rw.WritePacket(pkt); err != nil {
		t.Fatal(err.Error())
	}
	pktb := &StreamInit{}
	_, err := rw.ReadPacket(func(pktType uint32) (Packet, error) {
		if pktType != pkt.PacketType() {
			return nil, fmt.Errorf("Got pkt type %d, expected %d", pktType, pkt.PacketType())
		}
		return pktb, nil
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	if pktb.StreamType != pkt.StreamType {
		t.Fatalf("Got stream type %s, expected %s", pktb.StreamType, pkt.GetStreamType())
	}
}
