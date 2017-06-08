package session

// PacketType returns the packet type of the stream init packet.
func (*StreamInit) PacketType() uint32 {
	return 1
}
