package circuit

import (
	"errors"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
)

func (c *sessionControlState) handleCircuitTermination(pkt *CircuitProbe) error {
	return nil // TODO
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

	if pr.Destination.MatchesIdentity(c.config.LocalIdentity) {
		l.Debug("Probe (with destination us): %v", summaryShort)
		return c.handleCircuitTermination(pkt)
	}

	l.Debug("Probe: %v", summaryShort)
	backwardInterface := c.config.Session.GetInterface() // asserted != nil elsewhere
	backwardInterIdent := backwardInterface.Identifier()

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

		found := originalHopsIds.FindPartialHash(p.GetPartialHash())
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
