package session

// PacketType returns the packet type of the stream init packet.
func (p *ControlSessionInit) PacketType() uint32 {
	return 2
}

// ControlPacketIdentifier identifies Control packets.
var ControlPacketIdentifier = NewPacketIdentifier()

func init() {
	ControlPacketIdentifier.AddPacketType(
		func() Packet { return &ControlSessionInit{} },
	)
}
