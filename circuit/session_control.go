package circuit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/fuserobotics/quic-channel/signature"
	"github.com/fuserobotics/quic-channel/timestamp"
	"github.com/golang/protobuf/proto"
)

// sessionNonceLen is the session nonce length we use.
const sessionNonceLen = 32

// sessionNonceMin is the minimum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMin = 20

// sessionNonceMin is the maximum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMax = 100

// sessionControlState is the state for the session's control data.
type sessionControlState struct {
	context        context.Context
	config         *session.StreamHandlerConfig
	packets        chan packet.Packet
	keepAliveTimer *time.Timer

	initTimestamp   time.Time
	peerIdentity    *identity.ParsedIdentity
	localPrivateKey *rsa.PrivateKey

	activeHandlerMtx sync.Mutex
	activeHandler    *controlStreamHandler

	activePacketHandler func(pkt packet.Packet) error
	challengeNonce      []byte
}

// newSessionControlState builds a new control state.
func newSessionControlState(
	ctx context.Context,
	config *session.StreamHandlerConfig,
) *sessionControlState {
	s := &sessionControlState{
		context: ctx,
		config:  config,
		packets: make(chan packet.Packet, 5),
	}
	s.activePacketHandler = s.handleHandshakePacket
	if !config.Session.IsInitiator() {
		s.initTimestamp = time.Now()
	}
	return s
}

// handleControl manages the control state of the session.
func (s *sessionControlState) handleControl() error {
	ctx := s.context
	l := s.config.Log
	s.keepAliveTimer = time.NewTimer(keepAliveFrequency)
	if !s.config.Session.IsInitiator() {
		s.keepAliveTimer.Stop()
		if err := s.sendChallenge(); err != nil {
			return err
		}
	}
	for {
		var packet packet.Packet
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-s.keepAliveTimer.C:
			if err := s.sendKeepAlive(); err != nil {
				return err
			}
			s.keepAliveTimer.Reset(keepAliveFrequency)
			continue
		case packet = <-s.packets:
		}

		if _, ok := packet.(*KeepAlive); !ok {
			l.Debugf("Got control packet: %#v", packet)
		}

		if err := s.activePacketHandler(packet); err != nil {
			return err
		}
	}
}

// handleControlPacket handles packets after the handshake is complete.
func (c *sessionControlState) handleControlPacket(packet packet.Packet) error {
	switch pkt := packet.(type) {
	case *KeepAlive:
		c.config.Session.ResetInactivityTimeout(inactivityTimeout)
	default:
		c.config.Log.Warnf("Unhandled packet: %#v\n", pkt)
	}

	return nil
}

// handleHandshakePacket handles the handshake sequence.
func (c *sessionControlState) handleHandshakePacket(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr == nil {
			c.activePacketHandler = c.handleControlPacket
			err := c.config.Session.GetManager().OnSessionReady(&session.SessionReadyDetails{
				Session:            c.config.Session,
				InitiatedTimestamp: c.initTimestamp,
				PeerIdentity:       c.peerIdentity,
			})
			if err != nil {
				handleErr = err
				return
			}

			c.config.Session.ResetInactivityTimeout(inactivityTimeout)
			c.keepAliveTimer.Reset(keepAliveFrequency)

			pkh, err := c.peerIdentity.HashPublicKey()
			if err != nil {
				handleErr = err
				return
			}
			hashId := pkh.MarshalHashIdentifier()
			c.config.Log = c.config.Log.WithField("peer", hashId)

			c.config.Log.Debug("Session handshake complete")
		} else {
			c.config.Log.WithError(handleErr).Warn("Session handshake failed")
		}
	}()

	// initTimestamp can only be zero if we are the initiator
	if c.initTimestamp.IsZero() {
		switch pkt := packet.(type) {
		case *SessionInitChallenge:
			c.initTimestamp = timestamp.TimestampToTime(pkt.Timestamp)

			// respond with challenge response
			if err := c.sendChallengeResponse(pkt.Challenge); err != nil {
				return err
			}

			// assume it worked. the session will be closed with an error otherwise.
			return nil
		default:
		}
	}

	// peerIdentity can only be zero if we are not the initiator
	if c.peerIdentity == nil {
		switch pkt := packet.(type) {
		case *SessionInitResponse:
			// Verify the challenge response
			return c.verifyChallengeResponse(pkt.Signature)
		default:
		}
	}

	return errors.New("Unexpected handshake packet sequence.")
}

// sendPacket attempts to send a packet to the peer.
func (c *sessionControlState) sendPacket(packet packet.Packet) error {
	if c.activeHandler == nil {
		return errors.New("No control stream opened to send on.")
	}

	return c.activeHandler.config.PacketRw.WritePacket(packet)
}

// sendKeepAlive transmits a keep alive message to the stream.
func (c *sessionControlState) sendKeepAlive() error {
	c.activeHandlerMtx.Lock()
	defer c.activeHandlerMtx.Unlock()

	return c.sendPacket(&KeepAlive{})
}

// sendChallenge sends the challenge.
func (c *sessionControlState) sendChallenge() (sendChErr error) {
	nonce := make([]byte, sessionNonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return err
	}
	c.challengeNonce = nonce

	return c.sendPacket(&SessionInitChallenge{
		Challenge: &SessionChallenge{
			ChallengeNonce: nonce,
		},
		Timestamp: timestamp.TimeToTimestamp(c.initTimestamp),
	})
}

// sendChallengeResponse sends the challenge response.
func (c *sessionControlState) sendChallengeResponse(challenge *SessionChallenge) error {
	nonceLen := len(challenge.ChallengeNonce)
	if challenge == nil ||
		nonceLen < sessionNonceMin ||
		nonceLen > sessionNonceMax {
		return errors.New("Packet challenge was nil or of an invalid length.")
	}
	signedMsg, err := signature.NewSignedMessage(
		signature.ESignedMessageHash_HASH_SHA256,
		10,
		&SessionChallengeResponse{
			Challenge: challenge,
			Identity:  c.config.LocalIdentity.Identity,
		},
		c.config.LocalIdentity.GetPrivateKey(),
	)
	if err != nil {
		return err
	}

	return c.sendPacket(&SessionInitResponse{
		Signature: signedMsg,
	})
}

// verifyChallengeResponse checks the challenge response.
// Note: this is called on the server, so peerIdentity must be filled by this func.
func (c *sessionControlState) verifyChallengeResponse(response *signature.SignedMessage) error {
	// parse message first
	resp := &SessionChallengeResponse{}
	if err := proto.Unmarshal(response.Message, resp); err != nil {
		return err
	}
	if resp.Challenge == nil {
		return errors.New("Challenge response was empty.")
	}
	if resp.Identity == nil || len(resp.Identity.CertAsn1) < 1 {
		return errors.New("Peer identity in challenge response not given.")
	}

	ident := identity.NewParsedIdentity(resp.Identity)
	chain, err := ident.ParseCertificates()
	if err != nil {
		return err
	}
	if err := chain.Validate(c.config.CaCert); err != nil {
		return err
	}
	if bytes.Compare(resp.Challenge.ChallengeNonce, c.challengeNonce) != 0 {
		return fmt.Errorf("Challenge nonce did not match: %v != %v", resp.Challenge.ChallengeNonce, c.challengeNonce)
	}

	c.challengeNonce = nil
	c.peerIdentity = ident
	return nil
}
