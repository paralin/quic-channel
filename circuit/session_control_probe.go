package circuit

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/fuserobotics/quic-channel/conn"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/golang/protobuf/proto"
)

// pendingCircuitIdentityLookupTimeout is the time we will wait for peer identities before giving up.
var pendingCircuitIdentityLookupTimeout time.Duration = time.Duration(10) * time.Second

// pendingCircuitIdentityLookup is a circuit waiting for identity responses.
type pendingCircuitIdentityLookup struct {
	nonce         uint32
	pkt           *CircuitProbe
	timeoutCancel context.CancelFunc
	parsedRoute   *route.ParsedRoute
	hopIdents     route.RouteHopIdentities
	hops          route.RouteHops
}

// peerDbFromContext gets the peerdb from Context
func peerDbFromContext(c context.Context) (*peer.PeerDatabase, error) {
	peerDbInter := c.Value("peerdb")
	if peerDbInter == nil {
		return nil, errors.New("peer db not found in context")
	}
	return peerDbInter.(*peer.PeerDatabase), nil
}

// handleRouteProbe handles incoming route probes from peers.
func (c *sessionControlState) handleCircuitProbe(pkt *CircuitProbe) error {
	if pkt.Route == nil {
		return errors.New("circuit probe route was empty")
	}

	pr := route.BuildParsedRoute(pkt.Route)
	hops, err := pr.DecodeHops(c.config.CaCert)
	if err != nil {
		return err
	}

	peerDb, err := peerDbFromContext(c.context)
	if err != nil {
		return err
	}

	hopIdents := make(route.RouteHopIdentities, len(hops))
	var unidentifiedPeers []*identity.PeerIdentifier
	for i, hop := range hops {
		ident, err := peerDb.ByPartialHash(hop.Identity.MatchPublicKey)
		if err != nil {
			return err
		}
		if !ident.IsIdentified() {
			unidentifiedPeers = append(unidentifiedPeers, &identity.PeerIdentifier{
				MatchPublicKey: ident.GetPartialHash(false),
			})
			continue
		}
		hopIdents[i] = ident.GetIdentity()
	}

	pend := &pendingCircuitIdentityLookup{
		pkt:         pkt,
		parsedRoute: pr,
		hopIdents:   hopIdents,
		hops:        hops,
	}
	if len(unidentifiedPeers) > 0 {
		pendCtx, pendCtxCancel := context.WithCancel(c.context)
		pend.timeoutCancel = pendCtxCancel
		c.pendingPeerBouncesMtx.Lock()
		c.pendingPeerBouncesCtr++
		pend.nonce = uint32(c.pendingPeerBouncesCtr)
		c.pendingPeerBounces[pend.nonce] = pend
		go func() {
			select {
			case <-pendCtx.Done():
				return
			case <-time.After(pendingCircuitIdentityLookupTimeout):
				c.pendingPeerBouncesMtx.Lock()
				delete(c.pendingPeerBounces, pend.nonce)
				c.pendingPeerBouncesMtx.Unlock()
			}
		}()
		c.pendingPeerBouncesMtx.Unlock()

		return c.config.PacketRw.WriteProtoPacket(&CircuitPeerLookupRequest{
			QueryNonce:    pend.nonce,
			RequestedPeer: unidentifiedPeers,
		})
	}

	return c.finalizeCircuitProbe(pend)
}

// finalizeCircuitProbe finalizes a probe after identities are known.
func (c *sessionControlState) finalizeCircuitProbe(pend *pendingCircuitIdentityLookup) error {
	l := c.config.Log
	pr := pend.parsedRoute
	hopIdents := pend.hopIdents
	pkt := pend.pkt

	if err := pr.Verify(c.config.CaCert, hopIdents); err != nil {
		return err
	}

	backwardInterface := c.config.Session.GetInterface() // asserted != nil elsewhere
	backwardInterIdent := backwardInterface.Identifier()
	localPpid, err := c.config.LocalIdentity.ToPartialPeerIdentifier()
	if err != nil {
		return err
	}

	peerDb, err := peerDbFromContext(c.context)
	if err != nil {
		return err
	}

	if pr.Destination.MatchesIdentity(c.config.LocalIdentity) {
		l.Debug("Probe terminated with us")

		hop := route.NewHop(nil)
		hop.Identity = localPpid
		hop.BackwardInterface = backwardInterIdent
		if err := pr.AddHop(c.config.CaCert, hop, c.config.LocalIdentity); err != nil {
			return err
		}

		return c.handleCircuitTermination(pend.pkt, pr, peerDb, hopIdents)
	}

	// Instead of wasting memory, we will re-use the same route over and over.
	outgoingMessage := CircuitProbe{Route: pkt.Route}

	// For peer in connected peers...
	peerDb.ForEachPeer(func(p *peer.Peer) (peerErr error) {
		pl := l.WithField("peer", p.GetIdentifier())
		defer func() {
			if peerErr != nil {
				pl.WithError(peerErr).Warn("Skipping peer due to error")
				peerErr = nil
			}
		}()

		peerIdent := p.GetIdentity()
		if peerIdent == nil {
			return nil
		}

		peerKeyHash, err := peerIdent.HashPublicKey()
		if err != nil {
			return err
		}

		peerKeyIdentifier := &identity.PeerIdentifier{MatchPublicKey: (*peerKeyHash)[:]}
		found := pend.hopIdents.FindPartialHash(p.GetPartialHash(false))
		if found != nil {
			// Skip peer because it's already in the route.
			return nil
		}

		// For each circuit session (i.e. - interface)
		p.ForEachCircuitSession(func(s *session.Session) (innerSessErr error) {
			defer func() {
				if innerSessErr != nil {
					pl.WithError(innerSessErr).Warn("Error emitting probe on session")
					innerSessErr = nil
				}
			}()

			controlManager := s.GetOrPutData(1, nil)
			if controlManager == nil {
				return nil // Happens if the control stream is not open yet.
			}

			state, ok := controlManager.(*sessionControlState)
			if !ok {
				return nil
			}

			// Preventing split-horizon here is possible.
			// Just check the outgoing interface != incoming interface.
			// This feature is not yet useful, but here's where you would add it.
			outgoingInter := s.GetInterface()
			if outgoingInter == nil {
				return nil
			}
			outgoingInterIdent := outgoingInter.Identifier()

			msg := outgoingMessage
			rt := msg.Route

			nhop := route.NewHop(peerKeyIdentifier)
			nhop.Identity, err = c.config.LocalIdentity.ToPartialPeerIdentifier()
			if err != nil {
				return err
			}
			nhop.BackwardInterface = backwardInterIdent
			nhop.ForwardInterface = outgoingInterIdent

			if err := rt.AddHop(nhop, c.config.LocalIdentity.GetPrivateKey()); err != nil {
				return err
			}
			defer rt.PopHop()

			return state.sendPacket(&CircuitProbe{Route: rt})
		})

		return nil
	})

	return nil
}

// handleCircuitTermination handles a circuit probe reaching us.
func (c *sessionControlState) handleCircuitTermination(
	pkt *CircuitProbe,
	pr *route.ParsedRoute,
	peerDb *peer.PeerDatabase,
	hopIdents route.RouteHopIdentities,
) error {
	localAddr, err := c.config.LocalIdentity.ToIPv6Addr(c.config.CaCert)
	if err != nil {
		return err
	}

	hops, err := pr.DecodeHops(c.config.CaCert)
	if err != nil {
		return err
	}

	remotePkh := hops[0].Identity
	remoteAddr, err := hopIdents[0].ToIPv6Addr(c.config.CaCert)
	if err != nil {
		return err
	}

	routeData, err := proto.Marshal(pkt.Route)
	if err != nil {
		return err
	}

	est := &route.RouteEstablish{Route: routeData}
	if err := est.SignRoute(c.config.LocalIdentity.GetPrivateKey()); err != nil {
		return err
	}

	remotePeer, err := peerDb.ByPartialHash(hops[0].Identity.MatchPublicKey)
	if err != nil {
		return err
	}
	if remotePeer == nil {
		return errors.New("remote peer is not identified")
	}

	// TODO: use correct context
	pktWriteCh := make(chan *packet.RawPacket)
	pktReadCh := make(chan *packet.RawPacket)
	con := conn.NewChannelPacketConn(
		c.context,
		func(err error) {
			// TODO: handle packet conn close
		},
		pktReadCh,
		pktWriteCh,
		&net.UDPAddr{IP: localAddr, Port: 0},
		&net.UDPAddr{IP: remoteAddr, Port: 0},
	)

	// circuit probe just reached us, sending back a Establish.
	circ := newCircuit(
		c.context,
		c.config.TLSConfig,
		c.config.LocalIdentity,
		remotePeer,
		c.config.Session.GetInterface(),
		con,
		true,
		c.config.Log,
	)
	go circ.ManageCircuit()

	circuitStream, err := c.config.Session.OpenStream(
		session.StreamType(EStreamType_STREAM_CIRCUIT),
	)
	if err != nil {
		c.config.Log.WithError(err).Debug("Cannot open circuit stream")
		return err
	}

	// todo: close circuitstream here if necessary
	handler := circuitStream.(*circuitStreamHandler)
	handler.initPkt = &CircuitInit{RouteEstablish: est}
	if err := handler.config.PacketRw.WriteProtoPacket(handler.initPkt); err != nil {
		return err
	}
	handler.SetPacketWriteChan(pktWriteCh)
	handler.circuit = circ
	handler.circuitReadChan = pktReadCh

	c.config.Log.WithField("peer", remotePkh.MarshalHashIdentifier()).Debug("Built circuit")
	return nil
}
