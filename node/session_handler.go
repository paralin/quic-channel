package node

import (
	"errors"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/circuit"
	"github.com/fuserobotics/quic-channel/discovery"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/fuserobotics/quic-channel/timestamp"
)

// nodeSessionHandler handles session callbacks.
type nodeSessionHandler struct {
	*Node
}

// OnSessionReady is called when the session is finished initializing.
// Returning an error will terminate the session with the error.
func (h *nodeSessionHandler) OnSessionReady(details *session.SessionReadyDetails) error {
	pkh, err := details.PeerIdentity.HashPublicKey()
	if err != nil {
		return err
	}

	if details.PeerIdentity.CompareTo(h.localIdentity) {
		return errors.New("Cannot start session with ourselves!")
	}

	peer, err := h.peerDb.ByPartialHash(pkh[:])
	if err != nil {
		return err
	}

	if err := peer.SetIdentity(details.PeerIdentity); err != nil {
		return err
	}

	details.Session.SetStartTime(details.InitiatedTimestamp)
	ni := details.Session.GetInterface()
	if ni == nil {
		return fmt.Errorf("Unable to determine interface for addr %s", details.Session.GetLocalAddr().String())
	}
	log.
		WithField("peer", peer.GetIdentifier()).
		WithField("addr", details.Session.GetRemoteAddr().String()).
		WithField("iface", ni.Name).Debug("Interface determined")

	return peer.AddSession(details.Session)
}

// OnSessionClosed is called when a session is closed.
func (h *nodeSessionHandler) OnSessionClosed(sess *session.Session, err error) {
}

// CircuitBuilt is called when a circuit is built.
func (h *nodeSessionHandler) CircuitBuilt(c *circuit.Circuit) error {
	peer := c.GetPeer()
	if peer == nil {
		return errors.New("Circuit peer was nil.")
	}

	// builder := h.getCircuitBuilderForPeer(peer)
	// builder.builder.AddCircuit(c)
	return nil
}

// ChannelBuilt is called when a circuit channel is built.
func (h *nodeSessionHandler) ChannelBuilt(c *circuit.Circuit, s *session.SessionReadyDetails) error {
	peer := c.GetPeer()
	if peer == nil {
		return errors.New("circuit peer was nil")
	}

	builder := h.getCircuitBuilderForPeer(peer, true)
	builder.builder.PreventProbesUntil(
		timestamp.TimestampToTime(c.GetRoute().GetExpirationTimestamp()),
	)
	builder.builder.AddChannel(c, s.Session)
	return nil
}

// OnPeerEvent is called when a peer discovery event occurs
func (n *nodeSessionHandler) OnPeerEvent(eve *discovery.DiscoveryEvent) {
	func() (retErr error) {
		defer func() {
			if retErr != nil {
				log.WithError(retErr).Warn("Unable to process peer event")
			}
		}()

		if eve.ConnInfo == nil {
			return nil
		}

		peer, err := n.peerDb.ByPartialHash(eve.PeerId.MatchPublicKey)
		if err != nil {
			return err
		}

		le := log.
			WithField("peer", eve.PeerId.MarshalHashIdentifier()).
			WithField("addr", eve.ConnInfo.Address).
			WithField("iface", eve.Inter)

		sess := peer.SessionByInterface(eve.Inter)
		if sess != nil {
			return nil
		}

		le.Debug("Dialing [discovered via event]")

		go n.DialPeer(eve.ConnInfo.Address)
		return nil
	}()
}
