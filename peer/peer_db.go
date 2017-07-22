package peer

import (
	"crypto/sha256"
	"errors"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
)

// PeerDatabaseMarker is a marker on the context for the peer database.
var PeerDatabaseMarker = new(struct{ peerDbMarker int })

// PeerDatabase tracks known peers. Thread safe.
type PeerDatabase struct {
	mtx     sync.Mutex
	l       *log.Entry
	manager *peerDatabaseManager

	// identifiedPeers are peers we know the full public key hash for.
	identifiedPeers map[identity.PublicKeyHash]*Peer
	// ephemeralPeers are peers we know only part of the public key hash for.
	ephemeralPeers []*Peer
}

// peerDatabaseManager implements PeerManager
type peerDatabaseManager struct {
	*PeerDatabase
}

// NewPeerDatabase instantiates an empty peer database.
func NewPeerDatabase() *PeerDatabase {
	d := &PeerDatabase{
		l:               log.WithField("db", "peer"),
		identifiedPeers: make(map[identity.PublicKeyHash]*Peer),
	}
	d.manager = &peerDatabaseManager{PeerDatabase: d}
	return d
}

// ForEachPeer iterates over the peer database.
func (d *PeerDatabase) ForEachPeer(cb func(peer *Peer) error) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	for _, peer := range d.identifiedPeers {
		if err := cb(peer); err != nil {
			return err
		}
	}

	for _, peer := range d.ephemeralPeers {
		if err := cb(peer); err != nil {
			return err
		}
	}

	return nil
}

// ByPartialHash looks up a peer given a partial hash or full hash.
// If the peer doesn't already exist, it creates it.
// The partial hash length must be greater than 10.
func (d *PeerDatabase) ByPartialHash(partialHash []byte) (*Peer, error) {
	// we cannot identify by less than 10byte
	phl := len(partialHash)
	if phl < 10 {
		return nil, errors.New("Cannot identify peer with less than 10 bytes of public key hash.")
	}

	d.mtx.Lock()
	defer d.mtx.Unlock()

	if phl == sha256.Size {
		var pkh identity.PublicKeyHash
		copy(pkh[:], partialHash)
		p, ok := d.identifiedPeers[pkh]
		if ok {
			return p, nil
		}
	}

	for _, peer := range d.identifiedPeers {
		if peer.MatchesPartialHash(partialHash) {
			return peer, nil
		}
	}

	for _, peer := range d.ephemeralPeers {
		if peer.MatchesPartialHash(partialHash) {
			if len(partialHash) > len(peer.publicKeyHash) {
				peer.mtx.Lock()
				// prefer fully qualified hashes
				peer.publicKeyHash = partialHash
				peer.mtx.Unlock()
			}
			return peer, nil
		}
	}

	// Build the peer
	peer := NewPeer(d.manager, partialHash)
	hashId := peer.GetIdentifier()

	// Create the peer in the DB
	d.l.WithField("peer", hashId).Debug("Adding peer")

	if len(partialHash) == sha256.Size {
		var pk identity.PublicKeyHash
		copy(pk[:], partialHash)
		d.identifiedPeers[pk] = peer
	} else {
		d.ephemeralPeers = append(d.ephemeralPeers, peer)
	}
	return peer, nil
}

// removeEphemeralPeer removes a peer from the epehmeral array.
func (d *peerDatabaseManager) removeEphemeralPeer(peer *Peer) bool {
	for i, p := range d.ephemeralPeers {
		if p == peer {
			d.ephemeralPeers[i] = d.ephemeralPeers[len(d.ephemeralPeers)-1]
			d.ephemeralPeers[len(d.ephemeralPeers)-1] = nil
			d.ephemeralPeers = d.ephemeralPeers[:len(d.ephemeralPeers)-1]
			return true
		}
	}

	return false
}

// OnPeerUpdated is called by the peer when it's updated.
func (d *peerDatabaseManager) OnPeerUpdated(peer *Peer) {
	// note: extreme care around the mutexes is required here.
	if peer.IsFullyQualified() {
		var pkid identity.PublicKeyHash
		copy(pkid[:], peer.publicKeyHash)
		_, ok := d.identifiedPeers[pkid]
		if !ok {
			d.removeEphemeralPeer(peer)
			d.identifiedPeers[pkid] = peer
			d.l.WithField("peer", peer.GetIdentifier()).Debug("Peer became identified")
		}
	}
}
