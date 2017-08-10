package circuit

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/handshake"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/probe"
	"github.com/fuserobotics/quic-channel/session"
)

// sessionControlStateMarker is used as the key for sessionControlState
var sessionControlStateMarker = &struct{ sessionControlStateMarker uint32 }{}

// sessionControlState is the state for the session's control data.
type sessionControlState struct {
	context        context.Context
	config         *session.StreamHandlerConfig
	handshaker     *handshake.Handshaker
	packets        chan packet.Packet
	keepAliveTimer *time.Timer

	initTimestamp       time.Time
	peerIdentity        *identity.ParsedIdentity
	localPrivateKey     *rsa.PrivateKey
	expectChallengeResp bool

	activeHandlerMtx sync.Mutex
	activeHandler    *controlStreamHandler

	activePacketHandler func(pkt packet.Packet) error

	pendingPeerBouncesMtx sync.Mutex
	pendingPeerBouncesCtr int
	pendingPeerBounces    map[uint32]*pendingCircuitIdentityLookup

	probeTable *probe.ProbeTable
}

// newSessionControlState builds a new control state.
func newSessionControlState(
	ctx context.Context,
	config *session.StreamHandlerConfig,
) *sessionControlState {
	var s *sessionControlState
	s = &sessionControlState{
		context:            ctx,
		config:             config,
		packets:            make(chan packet.Packet, 5),
		pendingPeerBounces: make(map[uint32]*pendingCircuitIdentityLookup),
		handshaker: handshake.NewHandshaker(
			config.PacketRw,
			config.LocalIdentity,
			config.CaCert,
			func(peerIdentity *identity.ParsedIdentity) error {
				s.peerIdentity = peerIdentity
				return s.completeHandshake()
			},
			config.Session.IsInitiator(),
		),
		initTimestamp: time.Now(),
		probeTable:    ctx.Value(probe.ProbeTableMarker).(*probe.ProbeTable),
	}
	s.activePacketHandler = s.handshaker.HandlePacket
	return s
}

// handleControl manages the control state of the session.
func (s *sessionControlState) handleControl() error {
	ctx := s.context
	l := s.config.Log
	s.keepAliveTimer = time.NewTimer(keepAliveFrequency)
	if !s.config.Session.IsInitiator() {
		s.keepAliveTimer.Stop()
		if err := s.handshaker.SendChallenge(); err != nil {
			return err
		}
	}
	for {
		var packet packet.Packet
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-s.keepAliveTimer.C:
			if err := s.sendKeepAlive(); err != nil {
				return err
			}
			s.keepAliveTimer.Reset(keepAliveFrequency)
			continue
		case packet = <-s.packets:
		}

		if _, ok := packet.(*KeepAlive); !ok {
			l.Debugf("Got control packet: %#v", packet)
		}

		if err := s.activePacketHandler(packet); err != nil {
			return err
		}
	}
}

// completeHandshake is called to complete the handshake sequence.
func (s *sessionControlState) completeHandshake() error {
	s.activePacketHandler = s.handleControlPacket
	s.handshaker = nil
	err := s.config.Session.GetManager().OnSessionReady(&session.SessionReadyDetails{
		Session:            s.config.Session,
		InitiatedTimestamp: s.initTimestamp,
		PeerIdentity:       s.peerIdentity,
	})
	if err != nil {
		return err
	}

	s.config.Session.ResetInactivityTimeout(inactivityTimeout)
	s.keepAliveTimer.Reset(keepAliveFrequency)

	pkh, err := s.peerIdentity.HashPublicKey()
	if err != nil {
		return err
	}
	hashID := pkh.MarshalHashIdentifier()
	s.config.Log = s.config.Log.WithField("peer", hashID)

	// Transmit route probes.
	return s.transmitExistingProbes()
}

// handleControlPacket handles packets after the handshake is complete.
func (c *sessionControlState) handleControlPacket(packet packet.Packet) error {
	switch pkt := packet.(type) {
	case *KeepAlive:
		c.config.Session.ResetInactivityTimeout(inactivityTimeout)
	case *CircuitProbe:
		return c.handleCircuitProbe(pkt)
	case *CircuitPeerLookupResponse:
		nonce := pkt.QueryNonce
		pend := c.pendingPeerBounces[nonce]
		if pend == nil {
			return errors.New("received peer lookup response after request had timed out")
		}
		pend.timeoutCancel()
		c.pendingPeerBouncesMtx.Lock()
		delete(c.pendingPeerBounces, pend.nonce)
		c.pendingPeerBouncesMtx.Unlock()

		nextPeers := pkt.RequestedPeer
		for i, peer := range pend.hopIdents {
			if peer == nil {
				hopIdent := pend.hops[i].Identity
				if len(nextPeers) == 0 {
					return fmt.Errorf("Asked for identity for peer %s but didn't get it.", hopIdent.MarshalHashIdentifier())
				}

				np := nextPeers[0]
				nextPeers = nextPeers[1:]

				parsedIdent := identity.NewParsedIdentity(np)
				parsedIdentPkh, err := parsedIdent.HashPublicKey()
				if err != nil {
					return err
				}

				if !hopIdent.MatchesIdentity(parsedIdent) {
					return fmt.Errorf(
						"Asked for peer %s but got peer %s (result potentially out of order)",
						hopIdent.MarshalHashIdentifier(),
						parsedIdentPkh.MarshalHashIdentifier(),
					)
				}
				pend.hopIdents[i] = parsedIdent

				peerDb, err := peerDbFromContext(c.context)
				if err != nil {
					return err
				}
				pendPeer, err := peerDb.ByPartialHash((*parsedIdentPkh)[:])
				if err != nil {
					return err
				}
				if err := pendPeer.SetIdentity(parsedIdent); err != nil {
					return err
				}
			}
		}

		if err := c.finalizeCircuitProbe(pend); err != nil {
			return err
		}
	case *CircuitPeerLookupRequest:
		fmt.Printf("Got lookup request %#v\n", *pkt)
		nonce := pkt.QueryNonce
		reqPeers := pkt.RequestedPeer
		var result []*identity.Identity
		peerDb, err := peerDbFromContext(c.context)
		if err != nil {
			return err
		}

		for _, peer := range reqPeers {
			if err := peer.Verify(); err != nil {
				return err
			}

			np, err := peerDb.ByPartialHash(peer.MatchPublicKey)
			if err != nil {
				return err
			}
			if !np.IsIdentified() {
				return fmt.Errorf("Unknown peer: %s", peer.MarshalHashIdentifier())
			}
			result = append(result, np.GetIdentity().Identity)
		}

		response := &CircuitPeerLookupResponse{
			QueryNonce:    nonce,
			RequestedPeer: result,
		}

		fmt.Printf("Sending lookup response %#v\n", *response)
		err = c.config.PacketRw.WriteProtoPacket(response)
		if err != nil {
			return err
		}
		break
	default:
		c.config.Log.Warnf("Unhandled packet: %#v\n", pkt)
	}

	return nil
}

// sendPacket attempts to send a packet to the peer.
func (c *sessionControlState) sendPacket(packet packet.ProtoPacket) error {
	if c.activeHandler == nil {
		return errors.New("No control stream opened to send on.")
	}

	return c.activeHandler.config.PacketRw.WriteProtoPacket(packet)
}

// sendKeepAlive transmits a keep alive message to the stream.
func (c *sessionControlState) sendKeepAlive() error {
	c.activeHandlerMtx.Lock()
	defer c.activeHandlerMtx.Unlock()

	return c.sendPacket(&KeepAlive{})
}
