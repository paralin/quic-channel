package circuit

import (
	"errors"

	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/fuserobotics/quic-channel/timestamp"
)

// sessionNonceLen is the session nonce length we use.
const sessionNonceLen = 32

// sessionNonceMin is the minimum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMin = 20

// sessionNonceMin is the maximum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMax = 100

// completeHandshake is called to complete the handshake sequence.
func (c *sessionControlState) completeHandshake() error {
	c.activePacketHandler = c.handleControlPacket
	err := c.config.Session.GetManager().OnSessionReady(&session.SessionReadyDetails{
		Session:            c.config.Session,
		InitiatedTimestamp: c.initTimestamp,
		PeerIdentity:       c.peerIdentity,
	})
	if err != nil {
		return err
	}

	c.config.Session.ResetInactivityTimeout(inactivityTimeout)
	c.keepAliveTimer.Reset(keepAliveFrequency)

	pkh, err := c.peerIdentity.HashPublicKey()
	if err != nil {
		return err
	}
	hashId := pkh.MarshalHashIdentifier()
	c.config.Log = c.config.Log.WithField("peer", hashId)

	c.config.Log.Debug("Session handshake complete")
	return nil
}

// handleForwardHandshake handles step 1 of the handshake process as the initiator.
func (c *sessionControlState) handleForwardHandshakeInitiator(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			c.config.Log.WithError(handleErr).Warn("Session handshake failed")
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitChallenge:
		c.initTimestamp = timestamp.TimestampToTime(pkt.Timestamp)

		// build next challenge step
		nextChallenge, err := c.buildChallenge()
		if err != nil {
			return err
		}

		c.activePacketHandler = c.handleBackwardHandshake
		// respond with challenge response
		if err := c.sendChallengeResponse(pkt.Challenge, nextChallenge); err != nil {
			return err
		}

		return nil
	default:
		return errors.New("Expected init challenge as we are the initiator.")
	}

}

// handleForwardHandshakeReceiver handles the handshake as the receiver (not initiator).
func (c *sessionControlState) handleForwardHandshakeReceiver(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			c.config.Log.WithError(handleErr).Warn("Session handshake failed")
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitResponse:
		// Verify the challenge response
		if err := c.verifyChallengeResponse(pkt.Signature); err != nil {
			return err
		}

		// Respond to their challenge, if necessary.
		if pkt.Challenge != nil {
			if err := c.sendChallengeResponse(pkt.Challenge, nil); err != nil {
				return err
			}
		}

		// Complete the handshake
		return c.completeHandshake()
	default:
		return errors.New("Expected init challenge response as the receiver.")
	}
}

// handleBackwardHandshake handles step 2 of the handshake process.
func (c *sessionControlState) handleBackwardHandshake(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			c.config.Log.WithError(handleErr).Warn("Session handshake failed")
		} else {
			handleErr = c.completeHandshake()
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitResponse:
		return c.verifyChallengeResponse(pkt.Signature)
	default:
		return errors.New("Expected second challenge response.")
	}
}
