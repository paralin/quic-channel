package circuit

import (
	"errors"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/golang/protobuf/proto"
)

// handleCircuitTermination handles a circuit probe reaching us.
func (c *sessionControlState) handleCircuitTermination(pkt *CircuitProbe, pr *route.ParsedRoute) error {
	localAddr, err := c.config.LocalIdentity.ToIPv6Addr(c.config.CaCert)
	if err != nil {
		return err
	}

	_, hopIdents, err := pr.DecodeHops(c.config.CaCert)
	if err != nil {
		return err
	}

	remotePkh, err := hopIdents[0].HashPublicKey()
	if err != nil {
		return err
	}

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

	ch := make(chan []byte)
	circ := newCircuit(
		c.context,
		localAddr,
		remoteAddr,
		ch,
		est,
	)

	circuitStream, err := c.config.Session.OpenStream(session.StreamType(EStreamType_STREAM_CIRCUIT))
	if err != nil {
		return err
	}

	// todo: close circuitstream here if necessary
	handler := circuitStream.(*circuitStreamHandler)
	if err := handler.config.PacketRw.WritePacket(&CircuitInit{RouteEstablish: est}); err != nil {
		return err
	}
	handler.SetPacketWriteChan(ch)
	handler.circuit = circ

	c.config.Log.WithField("peer", remotePkh.MarshalHashIdentifier()).Debug("Built circuit")
	return nil
}

// handleRouteProbe handles incoming route probes from peers.
func (c *sessionControlState) handleCircuitProbe(pkt *CircuitProbe) error {
	l := c.config.Log

	if pkt.Route == nil {
		return errors.New("Circuit probe route was empty.")
	}

	pr := route.BuildParsedRoute(pkt.Route)
	if err := pr.Verify(c.config.CaCert); err != nil {
		return err
	}

	summaryShort, err := pr.SummaryShort(c.config.CaCert)
	if err != nil {
		return err
	}

	backwardInterface := c.config.Session.GetInterface() // asserted != nil elsewhere
	backwardInterIdent := backwardInterface.Identifier()

	if pr.Destination.MatchesIdentity(c.config.LocalIdentity) {
		l.Debugf("Probe (with destination us): %v", summaryShort)

		hop := route.NewHop(c.config.LocalIdentity.Identity, nil)
		hop.BackwardInterface = backwardInterIdent
		if err := pr.AddHop(c.config.CaCert, hop, c.config.LocalIdentity); err != nil {
			return err
		}

		return c.handleCircuitTermination(pkt, pr)
	}

	l.Debug("Probe: %v", summaryShort)

	// Instead of wasting memory, we will re-use the same route over and over.
	outgoingMessage := CircuitProbe{Route: pkt.Route}

	peerDbInter := c.context.Value("peerdb")
	if peerDbInter == nil {
		return errors.New("Peer db not found in Context.")
	}
	peerDb := peerDbInter.(*peer.PeerDatabase)

	_, originalHopsIds, err := pr.DecodeHops(c.config.CaCert)
	if err != nil {
		return err
	}

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

		found := originalHopsIds.FindPartialHash(p.GetPartialHash(false))
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

			nhop := route.NewHop(c.config.LocalIdentity.Identity, peerKeyIdentifier)
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
