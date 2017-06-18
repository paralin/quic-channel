package circuit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	pkt "github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/session"
)

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

// circuitStreamHandler manages circuit streams.
type circuitStreamHandler struct {
	circuit         *Circuit
	config          *session.StreamHandlerConfig
	inactivityTimer *time.Timer
	changeWriteChan chan (<-chan []byte)
	done            <-chan struct{}
	relayChan       chan []byte
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

	if h.circuit != nil {
		return errors.New("CircuitInit when the Circuit is already initialized!")
	}

	if pkt.RouteEstablish == nil || len(pkt.RouteEstablish.Route) == 0 {
		return errors.New("Malformed CircuitInit received.")
	}

	est := pkt.RouteEstablish
	pr, err := est.ParseVerifyRoute(h.config.CaCert)
	if err != nil {
		return err
	}

	compl, err := est.VerifySignatures(h.config.CaCert, pr)
	if err != nil {
		return err
	}

	hops, hopIdents, err := pr.DecodeHops(h.config.CaCert)
	if err != nil {
		return err
	}

	ourHopIdx := -1
	for i, hop := range hopIdents {
		if hop.CompareTo(h.config.LocalIdentity) {
			ourHopIdx = i
		}
	}
	if ourHopIdx == -1 {
		return errors.New("Could not find myself in the route")
	}

	// Determine the direction
	// Forward = prevous hop forward interface = us
	// Forward is therefore lastHopIdx < ourHopIdx
	var previousHopIdx int
	if ourHopIdx > 0 && hops[ourHopIdx-1].Next.MatchesIdentity(h.config.LocalIdentity) {
		previousHopIdx = ourHopIdx - 1
	} else if ourHopIdx < len(hops)-1 && hops[ourHopIdx+1].Next.MatchesIdentity(h.config.LocalIdentity) {
		previousHopIdx = ourHopIdx + 1
	} else {
		return errors.New("Cannot find previous hop in the chain / determine direction.")
	}

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

	if incomingSessionInterfaceId != expectedIncomingInterfaceId {
		return fmt.Errorf("Expected incoming interface %d but got %d", expectedIncomingInterfaceId, incomingSessionInterfaceId)
	}

	// Grab the control manager
	streamCtlInter := h.config.Session.GetOrPutData(1, nil)
	if streamCtlInter == nil {
		return errors.New("Got circuit build before control stream built.")
	}
	streamCtl := streamCtlInter.(*sessionControlState)
	peerId := streamCtl.peerIdentity
	if peerId == nil {
		return errors.New("Got circuit build before control handshake complete.")
	}

	// Ensure the previous hop came from the connected peer
	if !peerId.CompareTo(hopIdents[previousHopIdx]) {
		peerPkh, err := peerId.HashPublicKey()
		if err != nil {
			return err
		}
		expectedPeerPkh, err := hopIdents[previousHopIdx].HashPublicKey()
		if err != nil {
			return err
		}
		return fmt.Errorf(
			"Expected previous hop to be %s, but came from %s",
			expectedPeerPkh.MarshalHashIdentifier(),
			peerPkh.MarshalHashIdentifier(),
		)
	}

	if !compl {
		if err := est.SignRoute(h.config.LocalIdentity.GetPrivateKey()); err != nil {
			return err
		}
	}

	if ourHopIdx == 0 || ourHopIdx == len(hops)-1 {
		// Circuit terminates with us.
		localAddr, err := h.config.LocalIdentity.ToIPv6Addr(h.config.CaCert)
		if err != nil {
			return err
		}

		peerIdent := hopIdents[len(hops)-1-ourHopIdx]
		peerPkh, err := peerIdent.HashPublicKey()
		if err != nil {
			return err
		}

		peerAddr, err := peerIdent.ToIPv6Addr(h.config.CaCert)
		if err != nil {
			return err
		}

		pktWriteCh := make(chan []byte)
		circ := newCircuit(
			ctx,
			&net.UDPAddr{
				IP:   localAddr,
				Port: int(h.config.Stream.StreamID()),
			},
			&net.UDPAddr{
				IP:   peerAddr,
				Port: 5,
			},
			pktWriteCh,
			est,
		)
		h.SetPacketWriteChan(pktWriteCh)
		_ = circ

		h.config.Log.WithField("peer", peerPkh.MarshalHashIdentifier()).Debug("Built circuit")

		// TODO:
		// If !compl we should send the establish back again after.
		return nil
	}

	nextHopIdx := ourHopIdx - (previousHopIdx - ourHopIdx)
	// nextHop := hops[nextHopIdx]
	nextHopIdent := hopIdents[nextHopIdx]
	nextHopPkh, err := nextHopIdent.HashPublicKey()
	if err != nil {
		return err
	}

	// Circuit terminates elsewhere. Find the peer.
	peerDbInter := ctx.Value("peerdb")
	if peerDbInter == nil {
		return errors.New("Peer db not given.")
	}

	peerDb := peerDbInter.(*peer.PeerDatabase)
	peer, err := peerDb.ByPartialHash((*nextHopPkh)[:])
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
		if sessInterId != hops[ourHopIdx].ForwardInterface {
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

		h.config.Log.WithField("peer", nextHopPkh.MarshalHashIdentifier()).Debug("Built circuit relay")
		ch := make(chan []byte)
		circHandler.SetPacketWriteChan(ch)
		h.relayChan = ch

		chr := make(chan []byte)
		circHandler.relayChan = chr
		h.SetPacketWriteChan(chr)

		return circHandler.config.PacketRw.WritePacket(pkt)
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
