package circuit

import (
	"context"
	"math/rand"
	"sync"
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
	circuitBuilt       chan *Circuit
	circuitLost        chan *Circuit

	circMtx  sync.Mutex
	circuits []*Circuit
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
		circuitBuilt:       make(chan *Circuit, 10),
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

// AddCircuit adds a circuit to the builder.
func (cb *CircuitBuilder) AddCircuit(circ *Circuit) {
	cb.circuitBuilt <- circ
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
	OuterSelect:
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
		case <-preventProbesTimer.C:
			currentPreventProbesUntil = time.Time{}
			preventProbesTimer.Stop()
			startProbeTimer()
		case circ := <-cb.circuitBuilt:
			cb.circMtx.Lock()
			for _, ci := range cb.circuits {
				if ci == circ {
					break OuterSelect
				}
				if circ.GetOutgoingInterface() == ci.GetOutgoingInterface() {
					// Close the old duplicate circuit
					go ci.Close()
				}
			}
			cb.circuits = append(cb.circuits, circ)
			go circ.OnDone(func(c *Circuit) {
				cb.circMtx.Lock()
				defer cb.circMtx.Unlock()

				go func() {
					cb.circuitLost <- c
				}()

				for i, circ := range cb.circuits {
					if circ == c {
						cb.circuits[i] = cb.circuits[len(cb.circuits)-1]
						cb.circuits[len(cb.circuits)-1] = nil
						cb.circuits = cb.circuits[:len(cb.circuits)-1]
						return
					}
				}
			})
			cb.circMtx.Unlock()
		case c := <-cb.circuitLost:
			// TODO:
			// If a connection is desired, start the probe timer.
			// Otherwise, do nothing?
			_ = c
		case <-probeTimer.C:
			probeTimer.Stop()
			if len(cb.circuits) == 0 {
				if err := cb.emitCircuitProbe(); err != nil {
					return err
				}
			}
			startProbeTimer()
		}
	}
}

// emitCircuitProbe transmits a new circuit probe.
func (cb *CircuitBuilder) emitCircuitProbe() error {
	probe := route.NewRoute()
	probe.Destination = &identity.PeerIdentifier{
		MatchPublicKey: cb.peer.GetPartialHash(true),
	}

	circuitsByPeer := make(map[*peer.Peer]map[uint32]*Circuit)
	for _, circ := range cb.circuits {
		circuitsByInter := circuitsByPeer[circ.GetPeer()]
		if circuitsByInter == nil {
			circuitsByInter = make(map[uint32]*Circuit)
			circuitsByPeer[circ.GetPeer()] = circuitsByInter
		}
		circuitsByInter[circ.GetOutgoingInterface().Identifier()] = circ
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

		peerCircs := circuitsByPeer[p]
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
			// Avoid sending a probe the same direction we already have a circuit.
			if peerCircs != nil {
				_, ok := peerCircs[sIdent.Identifier()]
				if ok {
					return nil
				}
			}

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
