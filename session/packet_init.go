package session

import (
	"github.com/fuserobotics/quic-channel/packet"
)

// PacketType returns the packet type of the stream init packet.
func (*StreamInit) GetPacketType() packet.PacketType {
	return packet.PacketType(1)
}
