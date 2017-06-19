package node

import (
	"errors"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/circuit"
	"github.com/fuserobotics/quic-channel/session"
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

	builder := h.getCircuitBuilderForPeer(peer)
	builder.builder.AddCircuit(c)
	return nil
}
