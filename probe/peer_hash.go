package probe

import (
	"crypto/sha1"
	"encoding/binary"

	"github.com/fuserobotics/quic-channel/peer"
)

// peerInterfaceHash is the hash of a peer + interface
type peerInterfaceHash [sha1.Size]byte

// hashPeerAndInterface hashes a peer and interface ID.
func hashPeerAndInterface(peer *peer.Peer, interfaceId uint32) peerInterfaceHash {
	h := sha1.New()

	partialHash := peer.GetPartialHash(false)
	h.Write(partialHash)
	iidb := make([]byte, 4)
	binary.LittleEndian.PutUint32(iidb, interfaceId)
	h.Write(iidb)

	var res peerInterfaceHash
	copy(res[:], h.Sum(nil))
	return res
}
