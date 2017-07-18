package channel

import (
	"github.com/fuserobotics/quic-channel/handshake"
	"github.com/fuserobotics/quic-channel/packet"
)

// ControlPacketIdentifier identifies Control packets.
var ControlPacketIdentifier = packet.NewPacketIdentifier()

func init() {
	err := handshake.AddPacketTypes(ControlPacketIdentifier)
	/*
		if err == nil {
			err = ControlPacketIdentifier.AddPacketType(
				func() packet.ProtoPacket { return &MyMessage{} },
			)
		}
	*/
	if err != nil {
		panic(err)
	}
}
