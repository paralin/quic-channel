package circuit

import (
	"context"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/probe"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
)

// probePeriod is the length of time the network will re-transmit the probe.
var probePeriod time.Duration = time.Duration(30) * time.Second

// circuitSessionPair is a circuit and channel session
type circuitSessionPair struct {
	c *Circuit
	s *session.Session
}

// CircuitBuilder manages building circuits with a peer.
type CircuitBuilder struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	peer          *peer.Peer
	peerDb        *peer.PeerDatabase
	probeTable    *probe.ProbeTable
	lastProbeTime time.Time

	localIdentity *identity.ParsedIdentity

	channelBuilt    chan circuitSessionPair
	setPreventUntil chan time.Time
}

// NewCircuitBuilder creates a CircuitBuilder from a peer.
func NewCircuitBuilder(
	ctx context.Context,
	peer *peer.Peer,
	peerDb *peer.PeerDatabase,
	localIdentity *identity.ParsedIdentity,
	probeTable *probe.ProbeTable,
) *CircuitBuilder {
	cb := &CircuitBuilder{
		peer:          peer,
		peerDb:        peerDb,
		probeTable:    probeTable,
		localIdentity: localIdentity,

		channelBuilt:    make(chan circuitSessionPair, 10),
		setPreventUntil: make(chan time.Time, 1), // important that this is buffered with 1
	}
	cb.ctx, cb.ctxCancel = context.WithCancel(ctx)
	return cb
}

// AddChannel adds a circuit channel to the builder.
func (cb *CircuitBuilder) AddChannel(circ *Circuit, s *session.Session) {
	select {
	case <-cb.ctx.Done():
	case cb.channelBuilt <- circuitSessionPair{c: circ, s: s}:
	}
}

// PreventProbesUntil prevents route probes until a set time.
func (cb *CircuitBuilder) PreventProbesUntil(t time.Time) {
	select {
	case <-cb.ctx.Done():
	case cb.setPreventUntil <- t:
	}
}

// resetProbeTimer resets the probeTimer to the correct timing.
func (cb *CircuitBuilder) resetProbeTimer(timer *time.Timer, minimumNextProbe time.Time) {
	now := time.Now()
	nextProbe := now
	if !cb.lastProbeTime.IsZero() {
		timeTillNext := probePeriod - (now.Sub(cb.lastProbeTime))
		if timeTillNext > 0 {
			nextProbe = nextProbe.Add(timeTillNext)
		}
	}
	if nextProbe.Before(minimumNextProbe) {
		nextProbe = minimumNextProbe
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(nextProbe.Sub(now))
}

// BuilderWorker manages the CircuitBuilder.
func (cb *CircuitBuilder) BuilderWorker(emitInitial bool) error {
	var preventUntil time.Time
	probeTimer := time.NewTimer(probePeriod)
	log.WithField("peer", cb.peer.GetIdentifier()).Debug("Circuit builder started")

	if emitInitial {
		cb.emitCircuitProbe()
	}
	for {
		select {
		case <-cb.ctx.Done():
			return context.Canceled
		case nt := <-cb.setPreventUntil:
			if nt.After(preventUntil) {
				preventUntil = nt
				cb.resetProbeTimer(probeTimer, preventUntil)
			}
		case _ = <-cb.channelBuilt:
			// TODO: do something once we build a channel.
		case <-probeTimer.C:
			probeTimer.Stop()
			if err := cb.emitCircuitProbe(); err != nil {
				return err
			}
			cb.resetProbeTimer(probeTimer, preventUntil)
		}
	}
}

// emitCircuitProbe transmits a new circuit probe.
func (cb *CircuitBuilder) emitCircuitProbe() error {
	cb.lastProbeTime = time.Now()
	probe := route.NewRoute()
	probe.SetExpirationTime(time.Now().Add(probePeriod).Add(time.Duration(-2) * time.Second))
	probe.Destination = &identity.PeerIdentifier{
		MatchPublicKey: cb.peer.GetPartialHash(true),
	}
	localPkh, err := cb.localIdentity.HashPublicKey()
	if err != nil {
		return err
	}
	usPeer, err := cb.peerDb.ByPartialHash((*localPkh)[:])
	if err != nil {
		return err
	}

	pprobe := route.BuildParsedRoute(probe.Clone())
	pprobe.SetIncomingInterface(0)
	cb.probeTable.AddProbe(usPeer, 0, pprobe, true)

	return cb.peerDb.ForEachPeer(func(p *peer.Peer) (peerErr error) {
		if p == usPeer || !p.IsIdentified() {
			return nil
		}
		defer func() {
			if peerErr != nil {
				log.WithError(peerErr).Warn("Unable to emit circuit probe to peer")
				peerErr = nil
			}
		}()

		return p.ForEachCircuitSession(func(s *session.Session) (sessErr error) {
			defer func() {
				if sessErr != nil {
					log.WithError(sessErr).Debug("Unable to transmit route probe for session")
					sessErr = nil
				}
			}()

			sIdent := s.GetInterface()
			if sIdent == nil {
				return nil
			}

			controllerInter := s.GetOrPutData(sessionControlStateMarker, nil)
			if controllerInter == nil {
				return nil
			}
			controller := controllerInter.(*sessionControlState)

			netInter := s.GetInterface()
			if netInter == nil {
				return nil
			}
			netInterId := netInter.Identifier()

			var err error
			hop := route.NewHop(
				&identity.PeerIdentifier{MatchPublicKey: p.GetPartialHash(true)},
			)
			hop.ForwardInterface = netInterId
			hop.Identity, err = cb.localIdentity.ToPartialPeerIdentifier()
			if err != nil {
				return err
			}
			if err := probe.AddHop(hop, cb.localIdentity.GetPrivateKey()); err != nil {
				return err
			}
			defer probe.PopHop()

			return controller.sendPacket(&CircuitProbe{
				Route: probe,
			})
		})
	})
}

// Cancel cancels the CircuitBuilder
func (cb *CircuitBuilder) Cancel() {
	cb.ctxCancel()
}

// AddRoute adds a newly discovered route to the builder and the peer.
func (cb *CircuitBuilder) AddRoute(rt *route.ParsedRoute) {
}
