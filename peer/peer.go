package peer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/fuserobotics/quic-channel/zoo"
)

// PeerManager manages a peer.
type PeerManager interface {
	// OnPeerUpdated is called when the peer is updated.
	OnPeerUpdated(peer *Peer)
}

// Peer tracks a known peer.
type Peer struct {
	*zoo.Zoo

	mtx     sync.Mutex
	manager PeerManager

	// PublicKeyHash is the first N bytes of the public key hash.
	publicKeyHash []byte
	// Identity is the full identity of the peer, if known.
	identity *identity.ParsedIdentity
	// Circuit sessions
	circuitSessions []*session.Session
}

// NewPeer builds a new peer with a public key hash.
func NewPeer(manager PeerManager, publicKeyHash []byte) *Peer {
	return &Peer{
		Zoo:           zoo.NewZoo(),
		publicKeyHash: publicKeyHash,
		manager:       manager,
	}
}

// IsIdentified checks if we know this peer's identity.
func (p *Peer) IsIdentified() bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	return p.identity != nil
}

// IsFullyQualified checks if we know the full hash of this peer's public key.
func (p *Peer) IsFullyQualified() bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	return len(p.publicKeyHash) == sha256.Size
}

// GetIdentity returns the identity, if known.
func (p *Peer) GetIdentity() *identity.ParsedIdentity {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	return p.identity
}

// SetIdentity sets the peer identity.
func (p *Peer) SetIdentity(ident *identity.ParsedIdentity) error {
	if ident == nil {
		return errors.New("Identity can't be nil.")
	}

	if ident == p.identity {
		return nil
	}

	pkh, err := ident.HashPublicKey()
	if err != nil {
		return err
	}

	if !p.MatchesPartialHash(pkh[:]) {
		ia := pkh.MarshalHashIdentifier()
		ib := p.GetIdentifier()
		return fmt.Errorf("Peer.SetIdentity: given identity %s != peer identity %s", ia, ib)
	}

	p.mtx.Lock()
	p.publicKeyHash = pkh[:]
	p.identity = ident
	p.mtx.Unlock()

	p.manager.OnPeerUpdated(p)
	return nil
}

// GetIdentifier returns the 10 byte identifier of the peer.
func (p *Peer) GetIdentifier() string {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var pkPartial identity.PublicKeyPartialHash
	copy(pkPartial[:], p.publicKeyHash[:10])
	return (&pkPartial).MarshalHashIdentifier()
}

// GetPartialHash returns the peer's partial or full hash.
func (p *Peer) GetPartialHash(noLock bool) []byte {
	if !noLock {
		p.mtx.Lock()
		defer p.mtx.Unlock()
	}

	dat := make([]byte, len(p.publicKeyHash))
	copy(dat, p.publicKeyHash)
	return dat
}

// MatchesPartialHash checks if this peer is potentially the peer for partialHash.
func (p *Peer) MatchesPartialHash(partialHash []byte) bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	hash := p.publicKeyHash
	phl := len(partialHash)
	hl := len(hash)
	hlm := hl
	if phl < hlm {
		hlm = phl
	}
	return bytes.Compare(hash[:hlm], partialHash[:hlm]) == 0
}

// ForEachSession interates over the circuit sessions.
func (p *Peer) ForEachCircuitSession(cb func(sess *session.Session) error) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	for _, sess := range p.circuitSessions {
		if err := cb(sess); err != nil {
			return err
		}
	}
	return nil
}

// SessionByInterface looks up a peer session by interface.
func (p *Peer) SessionByInterface(inter uint32) *session.Session {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	for _, sess := range p.circuitSessions {
		ift := sess.GetInterface()
		if ift == nil {
			continue
		}

		if ift.Identifier() == inter {
			return sess
		}
	}

	return nil
}

// AddSession adds a session to the peer.
// Checks for duplicates.
func (p *Peer) AddSession(sess *session.Session) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	niid := sess.GetInterface().Identifier()
	sessionSt := sess.GetStartTime()
	for _, ss := range p.circuitSessions {
		ini := ss.GetInterface()
		if ini == nil {
			continue
		}

		iid := ini.Identifier()
		if iid == niid {
			st := ss.GetStartTime()
			userp := errors.New("Session userped by newer session")
			l := log.
				WithField("iface", iid).
				WithField("id1", ss.GetId()).
				WithField("id2", sess.GetId())
			if st.Before(sessionSt) {
				l.Debug("Userping 1")
				ss.CloseWithErr(userp)
			} else {
				l.Debug("Userping 2")
				return userp
			}
		}
	}

	sess.AddCloseCallback(p.RemoveSession)
	p.circuitSessions = append(p.circuitSessions, sess)
	go func() { log.WithField("peer", p.GetIdentifier()).Debug("Added session") }()
	return nil
}

// RemoveSession removes a session from the peer. Err parameter is ignored.
func (p *Peer) RemoveSession(sess *session.Session, err error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	for i, ses := range p.circuitSessions {
		if ses == sess {
			p.circuitSessions[i] = p.circuitSessions[len(p.circuitSessions)-1]
			p.circuitSessions[len(p.circuitSessions)-1] = nil
			p.circuitSessions = p.circuitSessions[:len(p.circuitSessions)-1]
			return
		}
	}
}
