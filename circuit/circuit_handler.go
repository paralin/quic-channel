package circuit

import (
	"fmt"

	"github.com/fuserobotics/quic-channel/session"
)

// circuitSessionHandler handles session callbacks.
type circuitSessionHandler struct {
	*Circuit
}

// OnSessionReady is called when the session is finished initializing.
// Returning an error will terminate the session with the error.
func (h *circuitSessionHandler) OnSessionReady(details *session.SessionReadyDetails) error {
	_, err := details.PeerIdentity.HashPublicKey()
	if err != nil {
		return err
	}

	if !details.PeerIdentity.CompareTo(h.peer.GetIdentity()) {
		foundPkh, err := details.PeerIdentity.HashPublicKey()
		if err != nil {
			return err
		}

		return fmt.Errorf(
			"channel: expected peer %s but handshook with %s",
			h.peer.GetIdentifier(),
			foundPkh.MarshalHashIdentifier(),
		)
	}

	details.Session.SetStartTime(details.InitiatedTimestamp)
	h.log.
		WithField("peer", h.peer.GetIdentifier()).
		Debug("Channel session ready")

	if h.builtHandler != nil {
		return h.builtHandler.ChannelBuilt(h.Circuit, details)
	}

	return nil
}

// OnSessionClosed is called when a session is closed.
func (h *circuitSessionHandler) OnSessionClosed(sess *session.Session, err error) {
	h.ctxCancel()
}
