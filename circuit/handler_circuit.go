package circuit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/network"
	pkt "github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
)

// CircuitBuiltHandler is assigned to the session data.
type CircuitBuiltHandler interface {
	// CircuitBuilt handles a new circuit. If returning err, will kill the circuit.
	CircuitBuilt(c *Circuit) error
}

// circuitBuildTimeout is the circuit handshake timeout
var circuitBuildTimeout = time.Duration(5) * time.Second

// circuitInactivityTimeout is the circuit inactivity timeout
var circuitInactivityTimeout = time.Duration(20) * time.Second

// circuitStreamHandlerBuilder builds circuit stream handlers.
type circuitStreamHandlerBuilder struct{}

// BuildHandler constructs the circuit stream handler.
func (b *circuitStreamHandlerBuilder) BuildHandler(config *session.StreamHandlerConfig) (session.StreamHandler, error) {
	return &circuitStreamHandler{
		config:          config,
		changeWriteChan: make(chan (<-chan []byte), 1),
	}, nil
}

// pendingCircuitInit contains information while we negotiate a circuit init
type pendingCircuitInit struct {
	pkt                      *CircuitInit
	parsedRoute              *route.ParsedRoute
	peerDb                   *peer.PeerDatabase
	hops                     route.RouteHops
	sentPeerLookup           bool
	ourHopIdx                int
	previousHopIdx           int
	streamCtl                *sessionControlState
	incomingSessionInterface *network.NetworkInterface
}

// circuitStreamHandler manages circuit streams.
type circuitStreamHandler struct {
	pendingInit     *pendingCircuitInit
	circuit         *Circuit
	established     bool
	initPkt         *CircuitInit
	config          *session.StreamHandlerConfig
	inactivityTimer *time.Timer
	changeWriteChan chan (<-chan []byte)
	done            <-chan struct{}
	relayChan       chan []byte
	relayHandler    *circuitStreamHandler
}

// SetPacketWriteChan sets the channel the session reads from for packets to write to the stream.
func (h *circuitStreamHandler) SetPacketWriteChan(ch <-chan []byte) {
	select {
	case h.changeWriteChan <- ch:
	case <-h.done:
	}
}

// handleCircuitInit handles the CircuitInit message.
func (h *circuitStreamHandler) handleCircuitInit(ctx context.Context, pkt *CircuitInit) error {
	if h.config.Initiator {
		return errors.New("Not expecting CircuitInit as the initiator.")
	}

	if pkt == nil {
		return errors.New("Cannot handle nil circuit init packet.")
	}

	if h.pendingInit != nil {
		return errors.New("CircuitInit with existing pending init in place!")
	}

	if h.circuit != nil || h.initPkt != nil {
		return errors.New("CircuitInit when the Circuit is already initialized!")
	}
	h.initPkt = pkt

	if pkt.RouteEstablish == nil || len(pkt.RouteEstablish.Route) == 0 {
		return errors.New("Malformed CircuitInit received.")
	}

	pendingInit := &pendingCircuitInit{pkt: pkt}
	est := pkt.RouteEstablish
	pr, err := est.ParseRoute(h.config.CaCert)
	if err != nil {
		return err
	}
	pendingInit.parsedRoute = pr

	peerDbInter := ctx.Value("peerdb")
	if peerDbInter == nil {
		return errors.New("Peer db not given.")
	}
	peerDb := peerDbInter.(*peer.PeerDatabase)
	pendingInit.peerDb = peerDb

	hops, err := pr.DecodeHops(h.config.CaCert)
	if err != nil {
		return err
	}
	pendingInit.hops = hops

	ourHopIdx := -1
	for i, hop := range hops {
		if hop.Identity.MatchesIdentity(h.config.LocalIdentity) {
			if ourHopIdx != -1 {
				return errors.New("We appear in the route twice.")
			}
			ourHopIdx = i
		}
	}
	if ourHopIdx == -1 {
		return errors.New("Could not find myself in the route")
	}
	pendingInit.ourHopIdx = ourHopIdx

	// Grab the control manager
	streamCtlInter := h.config.Session.GetOrPutData(1, nil)
	if streamCtlInter == nil {
		return errors.New("Got circuit build before control stream built.")
	}
	streamCtl := streamCtlInter.(*sessionControlState)
	pendingInit.streamCtl = streamCtl
	peerId := streamCtl.peerIdentity
	if peerId == nil {
		return errors.New("Got circuit build before control handshake complete.")
	}

	// Determine the direction
	// Forward = prevous hop forward interface = us
	// Forward is therefore lastHopIdx < ourHopIdx
	var previousHopIdx int
	if ourHopIdx > 0 && hops[ourHopIdx-1].Identity.MatchesIdentity(peerId) {
		previousHopIdx = ourHopIdx - 1
	} else if ourHopIdx < len(hops)-1 && hops[ourHopIdx+1].Identity.MatchesIdentity(peerId) {
		previousHopIdx = ourHopIdx + 1
	} else {
		return errors.New("Cannot find previous hop in the chain / determine direction.")
	}
	pendingInit.previousHopIdx = previousHopIdx

	forward := previousHopIdx < ourHopIdx
	var expectedIncomingInterfaceId uint32
	if forward {
		expectedIncomingInterfaceId = hops[previousHopIdx].ForwardInterface
	} else {
		expectedIncomingInterfaceId = hops[previousHopIdx].BackwardInterface
	}

	incomingSessionInterface := h.config.Session.GetInterface()
	if incomingSessionInterface == nil {
		return errors.New("Cannot determine incoming network interface.")
	}
	incomingSessionInterfaceId := incomingSessionInterface.Identifier()
	pendingInit.incomingSessionInterface = incomingSessionInterface

	if incomingSessionInterfaceId != expectedIncomingInterfaceId {
		return fmt.Errorf("Expected incoming interface %d but got %d", expectedIncomingInterfaceId, incomingSessionInterfaceId)
	}

	// Ensure the previous hop came from the connected peer
	if !hops[previousHopIdx].Identity.MatchesIdentity(peerId) {
		peerIdHash, err := peerId.HashPublicKey()
		if err != nil {
			return err
		}

		return fmt.Errorf(
			"Expected previous hop to be %s, but came from %s",
			hops[previousHopIdx].Identity.MarshalHashIdentifier(),
			peerIdHash.MarshalHashIdentifier(),
		)
	}

	return h.finalizeCircuitInit(pendingInit)
}

// finalizeCircuitInit attempts to finalize a pendingCircuitInit
func (h *circuitStreamHandler) finalizeCircuitInit(pi *pendingCircuitInit) error {
	var unknownPeers []*identity.PeerIdentifier
	hopIdents := make(route.RouteHopIdentities, len(pi.hops))
	hopPeers := make([]*peer.Peer, len(pi.hops))
	for i, hop := range pi.hops {
		ident := hop.Identity
		peer, err := pi.peerDb.ByPartialHash(ident.MatchPublicKey)
		if err != nil {
			return err
		}
		if !peer.IsIdentified() {
			unknownPeers = append(unknownPeers, ident)
			if pi.sentPeerLookup {
				return fmt.Errorf("Unknown peer in route after peer lookup: %s", ident.MarshalHashIdentifier())
			}
			pi.sentPeerLookup = true
		}
		hopIdents[i] = peer.GetIdentity()
		hopPeers[i] = peer
	}
	if len(unknownPeers) > 0 {
		h.pendingInit = pi
		return h.config.PacketRw.WritePacket(&CircuitPeerLookupRequest{
			QueryNonce:    1,
			RequestedPeer: unknownPeers,
		})
	}

	idx := -1
	est := pi.pkt.RouteEstablish
	compl, err := est.VerifySignatures(h.config.CaCert, pi.parsedRoute, func(ident *identity.PeerIdentifier) (*identity.ParsedIdentity, error) {
		idx++
		return hopIdents[idx], nil
	})
	if err != nil {
		return err
	}

	if !compl {
		if err := est.SignRoute(h.config.LocalIdentity.GetPrivateKey()); err != nil {
			return err
		}
	}

	if pi.ourHopIdx == 0 || pi.ourHopIdx == len(pi.hops)-1 {
		// Circuit terminates with us.
		localAddr, err := h.config.LocalIdentity.ToIPv6Addr(h.config.CaCert)
		if err != nil {
			return err
		}

		peerIdent := hopIdents[len(pi.hops)-1-pi.ourHopIdx]
		peer := hopPeers[len(pi.hops)-1-pi.ourHopIdx]
		peerAddr, err := peerIdent.ToIPv6Addr(h.config.CaCert)
		if err != nil {
			return err
		}

		pktWriteCh := make(chan []byte)
		circ := newCircuit(
			peer,
			localAddr,
			peerAddr,
			pktWriteCh,
			est,
			pi.incomingSessionInterface,
		)
		h.SetPacketWriteChan(pktWriteCh)
		h.circuit = circ

		fest := &CircuitEstablished{}
		if !compl {
			fest.FinalRouteEstablish = est
		}
		if err := h.config.PacketRw.WritePacket(fest); err != nil {
			return err
		}

		h.config.Log.Debug("Circuit finalized")
		handlerInter := h.config.Session.GetOrPutData(2, nil)
		if handlerInter != nil {
			handler := handlerInter.(CircuitBuiltHandler)
			if err := handler.CircuitBuilt(circ); err != nil {
				return err
			}
		}
		h.inactivityTimer.Reset(circuitInactivityTimeout)

		return nil
	}

	nextHopIdx := pi.ourHopIdx - (pi.previousHopIdx - pi.ourHopIdx)
	// nextHop := hops[nextHopIdx]
	nextHopIdent := hopIdents[nextHopIdx]
	nextHopPkh, err := nextHopIdent.HashPublicKey()
	if err != nil {
		return err
	}

	// Circuit terminates elsewhere. Find the peer.
	peer, err := pi.peerDb.ByPartialHash((*nextHopPkh)[:])
	if err != nil {
		return err
	}
	if peer.IsIdentified() {
		peerIdent := peer.GetIdentity()
		if !peerIdent.CompareTo(nextHopIdent) {
			return fmt.Errorf("Matched peer %s but should have matched %s!", peer.GetIdentifier(), nextHopPkh.MarshalHashIdentifier())
		}
	} else {
		if err := peer.SetIdentity(nextHopIdent); err != nil {
			return err
		}
	}

	// Match the session with the same interface.
	found := false
	err = peer.ForEachCircuitSession(func(sess *session.Session) error {
		sessInter := sess.GetInterface()
		if sessInter == nil {
			return nil
		}

		sessInterId := sessInter.Identifier()
		if sessInterId != pi.hops[pi.ourHopIdx].ForwardInterface {
			return nil
		}

		found = true
		handler, err := sess.OpenStream(session.StreamType(EStreamType_STREAM_CIRCUIT))
		if err != nil {
			return err
		}
		circHandler, ok := handler.(*circuitStreamHandler)
		if !ok {
			return errors.New("Expected STREAM_CIRCUIT to yield a circuitStreamHandler")
		}

		h.config.Log.
			WithField("peer1", pi.hops[pi.previousHopIdx].Identity.MarshalHashIdentifier()).
			WithField("peer2", nextHopPkh.MarshalHashIdentifier()).
			Debug("Built circuit relay")
		ch := make(chan []byte)
		circHandler.SetPacketWriteChan(ch)
		h.relayChan = ch
		h.relayHandler = circHandler

		chr := make(chan []byte)
		circHandler.relayChan = chr
		circHandler.initPkt = h.initPkt
		circHandler.relayHandler = h
		h.SetPacketWriteChan(chr)

		return circHandler.config.PacketRw.WritePacket(pi.pkt)
	})
	if err != nil {
		return err
	}
	if !found {
		return errors.New("Peer unavailable at this time.")
	}
	return nil
}

// readPump manages reading from the circuit stream.
func (h *circuitStreamHandler) readPump(ctx context.Context) error {
	for {
		packet, err := h.config.PacketRw.ReadPacket(
			pkt.PacketIdentifierFunc(CircuitPacketIdentifier.IdentifyPacket),
		)
		if err != nil {
			return err
		}
		if packet == nil {
			return errors.New("Got nil packet.")
		}

		switch pkt := packet.(type) {
		case *CircuitInit:
			if err := h.handleCircuitInit(ctx, pkt); err != nil {
				return err
			}
		case *CircuitPacket:
			if h.relayChan != nil {
				select {
				case <-ctx.Done():
					return context.Canceled
				case h.relayChan <- pkt.PacketData:
					continue
				}
			}

			if h.circuit == nil {
				return errors.New("Circuit packet received before circuit build complete")
			}
			if len(pkt.PacketData) == 0 {
				continue
			}
			if err := h.circuit.handlePacket(pkt.PacketData); err != nil {
				return err
			}
		case *CircuitPeerLookupRequest:
			// TODO: some condition here?
			peerDb, err := peerDbFromContext(ctx)
			if err != nil {
				return err
			}
			resp := &CircuitPeerLookupResponse{QueryNonce: pkt.QueryNonce}
			for _, peerId := range pkt.RequestedPeer {
				peer, err := peerDb.ByPartialHash(peerId.MatchPublicKey)
				if err != nil {
					return err
				}
				if !peer.IsIdentified() {
					return fmt.Errorf("Peer %s not identified.", peer.GetIdentifier())
				}
				resp.RequestedPeer = append(resp.RequestedPeer, peer.GetIdentity().Identity)
			}
			if len(resp.RequestedPeer) == 0 {
				return errors.New("Got empty CircuitPeerLookupRequest")
			}
			if err := h.config.PacketRw.WritePacket(resp); err != nil {
				return err
			}
		case *CircuitPeerLookupResponse:
			pi := h.pendingInit
			if pi == nil {
				return errors.New("Unsolicited peer lookup response")
			}
			h.pendingInit = nil
			for _, peerId := range pkt.RequestedPeer {
				parsedId := identity.NewParsedIdentity(peerId)
				idPkh, err := parsedId.HashPublicKey()
				if err != nil {
					return err
				}
				peer, err := pi.peerDb.ByPartialHash((*idPkh)[:])
				if err != nil {
					return err
				}
				if err := peer.SetIdentity(parsedId); err != nil {
					return err
				}
			}
			return h.finalizeCircuitInit(pi)
		case *CircuitEstablished:
			if h.established {
				return errors.New("Received CircuitEstablished multiple times.")
			}

			// h.pendingCircuit -> h.onCircuitFinalized() - ?
			h.config.Log.Debug("Circuit established confirm received")
			h.inactivityTimer.Reset(circuitInactivityTimeout)
			h.established = true

			if h.initPkt == nil || (h.relayChan == nil && h.circuit == nil) {
				return errors.New("CircuitEstablished received before Circuit was established locally.")
			}

			peerDb, err := peerDbFromContext(ctx)
			if err != nil {
				return err
			}

			if pkt.FinalRouteEstablish != nil {
				if bytes.Compare(pkt.FinalRouteEstablish.Route, h.initPkt.RouteEstablish.Route) != 0 {
					return errors.New("Final RouteEstablish does not match built route.")
				}
				pr, err := pkt.FinalRouteEstablish.ParseRoute(h.config.CaCert)
				if err != nil {
					return err
				}
				if !pr.IsComplete(h.config.CaCert) {
					return errors.New("Expected CircuitEstablishFinalized route to be complete.")
				}
				compl, err := pkt.FinalRouteEstablish.VerifySignatures(h.config.CaCert, pr, func(peerId *identity.PeerIdentifier) (*identity.ParsedIdentity, error) {
					peer, err := peerDb.ByPartialHash(peerId.MatchPublicKey)
					if err != nil {
						return nil, err
					}
					if !peer.IsIdentified() {
						return nil, fmt.Errorf("Unknown peer in route: %s", peerId.MarshalHashIdentifier())
					}
					return peer.GetIdentity(), nil
				})
				if err != nil {
					return err
				}
				if !compl {
					return errors.New("Expected CircuitEstablishFinalized route to be fully signed.")
				}
				if h.circuit != nil {
					h.circuit.routeEstablish = pkt.FinalRouteEstablish
				}
			}

			if h.circuit != nil {
				h.config.Log.Debug("Circuit finalized")
				handlerInter := h.config.Session.GetOrPutData(2, nil)
				if handlerInter != nil {
					handler := handlerInter.(CircuitBuiltHandler)
					if err := handler.CircuitBuilt(h.circuit); err != nil {
						return err
					}
				}
				if h.relayHandler != nil {
					if err := h.relayHandler.config.PacketRw.WritePacket(pkt); err != nil {
						return err
					}
				}
			}

		default:
			return fmt.Errorf("Unexpected circuit packet type %d", pkt.GetPacketType())
		}
	}
}

// writePacket writes a packet to the circuit.
func (h *circuitStreamHandler) writePacket(data []byte) error {
	return h.config.PacketRw.WritePacket(&CircuitPacket{
		PacketData: data,
	})
}

// Handle manages the circuit stream.
func (h *circuitStreamHandler) Handle(ctx context.Context) error {
	h.done = ctx.Done()
	h.inactivityTimer = time.NewTimer(circuitBuildTimeout)

	readErr := make(chan error, 1)
	go func() { // start reading
		readErr <- h.readPump(ctx)
	}()

	var writeChan <-chan []byte
	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case err := <-readErr:
			return err
		case <-h.inactivityTimer.C:
			return errors.New("Timeout exceeded.")
		case ch := <-h.changeWriteChan:
			writeChan = ch
			continue
		case pkt := <-writeChan:
			if err := h.writePacket(pkt); err != nil {
				return err
			}
		}
	}
}

// StreamType returns the type of stream this handles.
func (h *circuitStreamHandler) StreamType() session.StreamType {
	return session.StreamType(EStreamType_STREAM_CIRCUIT)
}
