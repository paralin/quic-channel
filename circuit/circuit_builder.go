package circuit

import (
	"context"
	"math/rand"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
)

// minimumProbeSeconds are the minimum seconds between probe attempts.
var minimumProbeSeconds = 10

// randomProbeSeconds are the randomization deviation of the minimum
var randomProbeSeconds = 20

// CircuitBuilder manages building circuits with a peer.
type CircuitBuilder struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	peer          *peer.Peer
	peerDb        *peer.PeerDatabase
	localIdentity *identity.ParsedIdentity

	preventProbesUntil chan *time.Time
}

// NewCircuitBuilder creates a CircuitBuilder from a peer.
func NewCircuitBuilder(
	ctx context.Context,
	peer *peer.Peer,
	peerDb *peer.PeerDatabase,
	localIdentity *identity.ParsedIdentity,
) *CircuitBuilder {
	cb := &CircuitBuilder{
		peer:          peer,
		peerDb:        peerDb,
		localIdentity: localIdentity,

		preventProbesUntil: make(chan *time.Time, 1),
	}
	cb.ctx, cb.ctxCancel = context.WithCancel(ctx)
	return cb
}

// When building a circuit:
// OpenStream() circuit stream
// Construct Circuit, SetPacketWriteChan to common channel
// finalize Circuit.

// PreventProbesUntil instructs the CircuitBuilder to prevent emitting route probes until a time.
// Sending nil removes any existing timer and allows probes immediately.
func (cb *CircuitBuilder) PreventProbesUntil(t *time.Time) {
	cb.preventProbesUntil <- t
}

// BuilderWorker manages the CircuitBuilder.
func (cb *CircuitBuilder) BuilderWorker() error {
	var currentPreventProbesUntil time.Time
	preventProbesTimer := time.NewTimer(time.Duration(1) * time.Minute)
	preventProbesTimer.Stop()

	probeTimer := time.NewTimer(time.Duration(1) * time.Minute)
	probeTimer.Stop()
	startProbeTimer := func() {
		duration := rand.Intn(randomProbeSeconds) + minimumProbeSeconds
		probeTimer.Reset(time.Duration(duration) * time.Second)
	}
	startProbeTimer()
	log.WithField("peer", cb.peer.GetIdentifier()).Debug("Circuit builder started")

	for {
		select {
		case <-cb.ctx.Done():
			return context.Canceled
		// Manage prevent probes timer
		case prevUntil := <-cb.preventProbesUntil:
			if prevUntil == nil {
				preventProbesTimer.Stop()
				if !currentPreventProbesUntil.IsZero() {
					startProbeTimer()
				}
				currentPreventProbesUntil = time.Time{}
				continue
			}

			now := time.Now()
			if prevUntil.After(now) {
				continue
			}
			if prevUntil.After(currentPreventProbesUntil) {
				currentPreventProbesUntil = *prevUntil
				preventProbesTimer.Reset(prevUntil.Sub(now))
			}
			continue
		case <-preventProbesTimer.C:
			currentPreventProbesUntil = time.Time{}
			preventProbesTimer.Stop()
			startProbeTimer()
			continue
		case <-probeTimer.C:
			probeTimer.Stop()
			if err := cb.emitCircuitProbe(); err != nil {
				return err
			}
			startProbeTimer()
			continue
		}
	}
}

// emitCircuitProbe transmits a new circuit probe.
func (cb *CircuitBuilder) emitCircuitProbe() error {
	probe := route.NewRoute()
	probe.Destination = &identity.PeerIdentifier{
		MatchPublicKey: cb.peer.GetPartialHash(true),
	}

	return cb.peerDb.ForEachPeer(func(p *peer.Peer) (peerErr error) {
		defer func() {
			if peerErr != nil {
				log.WithError(peerErr).Warn("Unable to emit circuit probe to peer")
				peerErr = nil
			}
		}()

		if !p.IsIdentified() {
			return nil
		}

		return p.ForEachCircuitSession(func(s *session.Session) (sessErr error) {
			defer func() {
				if sessErr != nil {
					log.WithError(sessErr).Debug("Unable to transmit route probe for session")
					sessErr = nil
				}
			}()

			controllerInter := s.GetOrPutData(1, nil)
			if controllerInter == nil {
				return nil
			}
			controller := controllerInter.(*sessionControlState)

			netInter := s.GetInterface()
			if netInter == nil {
				return nil
			}
			netInterId := netInter.Identifier()

			hop := route.NewHop(
				cb.localIdentity.Identity,
				&identity.PeerIdentifier{MatchPublicKey: p.GetPartialHash(true)},
			)
			hop.ForwardInterface = netInterId
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
