package circuit

import (
	"errors"

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

	if details.PeerIdentity.CompareTo(h.peer.GetIdentity()) {
		return errors.New("unexpected peer on other end of channel")
	}

	details.Session.SetStartTime(details.InitiatedTimestamp)
	h.log.
		WithField("peer", h.peer.GetIdentifier()).
		Debug("Channel session ready")

	return nil // TODO: peer.AddChannelSession(details.Session) ?
}

// OnSessionClosed is called when a session is closed.
func (h *circuitSessionHandler) OnSessionClosed(sess *session.Session, err error) {
	h.ctxCancel()
}
