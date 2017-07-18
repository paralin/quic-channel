package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/signature"
	"github.com/fuserobotics/quic-channel/timestamp"
	"github.com/golang/protobuf/proto"

	log "github.com/Sirupsen/logrus"
)

// sessionNonceLen is the session nonce length we use.
const sessionNonceLen = 32

// sessionNonceMin is the minimum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMin = 20

// sessionNonceMin is the maximum acceptable nonce length. DO NOT CHANGE.
const sessionNonceMax = 100

// Handshaker manages handshaking a connection.
type Handshaker struct {
	rw             *packet.PacketReadWriter
	ident          *identity.ParsedIdentity
	peerIdent      *identity.ParsedIdentity
	caCert         *x509.Certificate
	challengeNonce []byte
	completed      func(peerIdentity *identity.ParsedIdentity) error
	handler        func(packet packet.Packet) error
}

// NewHandshaker builds a handshaker.
func NewHandshaker(
	pktRw *packet.PacketReadWriter,
	ident *identity.ParsedIdentity,
	caCert *x509.Certificate,
	completed func(peerIdentity *identity.ParsedIdentity) error,
	initiator bool,
) *Handshaker {
	h := &Handshaker{
		rw:        pktRw,
		ident:     ident,
		completed: completed,
		caCert:    caCert,
	}

	if initiator {
		h.handler = h.handleForwardHandshakeInitiator
	} else {
		h.handler = h.handleForwardHandshakeReceiver
	}

	return h
}

// HandlePacket handles a packet.
func (h *Handshaker) HandlePacket(packet packet.Packet) error {
	return h.handler(packet)
}

// SendChallenge sends the first challenge (as the server).
func (h *Handshaker) SendChallenge() (sendChErr error) {
	challenge, err := h.buildChallenge()
	if err != nil {
		return err
	}

	return h.sendPacket(&SessionInitChallenge{
		Challenge: challenge,
		Timestamp: timestamp.TimeToTimestamp(time.Now()),
	})
}

// handleForwardHandshake handles step 1 of the handshake process as the initiator.
func (h *Handshaker) handleForwardHandshakeInitiator(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			log.WithError(handleErr).Warn("session handshake failed")
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitChallenge:
		// build next challenge step
		nextChallenge, err := h.buildChallenge()
		if err != nil {
			return err
		}

		h.handler = h.handleBackwardHandshake
		// respond with challenge response
		if err := h.sendChallengeResponse(pkt.Challenge, nextChallenge); err != nil {
			return err
		}

		return nil
	default:
		return errors.New("expected init challenge as we are the initiator")
	}

}

// handleForwardHandshakeReceiver handles the handshake as the receiver (not initiator).
func (h *Handshaker) handleForwardHandshakeReceiver(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			log.WithError(handleErr).Warn("Session handshake failed")
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitResponse:
		// Verify the challenge response
		if err := h.verifyChallengeResponse(pkt.Signature); err != nil {
			return err
		}

		// Respond to their challenge, if necessary.
		if pkt.Challenge != nil {
			if err := h.sendChallengeResponse(pkt.Challenge, nil); err != nil {
				return err
			}
		}

		// Complete the handshake
		return h.completed(h.peerIdent)
	default:
		return errors.New("expected init challenge response as the receiver")
	}
}

// handleBackwardHandshake handles step 2 of the handshake process.
func (h *Handshaker) handleBackwardHandshake(packet packet.Packet) (handleErr error) {
	defer func() {
		if handleErr != nil {
			log.WithError(handleErr).Warn("Session handshake failed")
		} else {
			handleErr = h.completed(h.peerIdent)
		}
	}()

	switch pkt := packet.(type) {
	case *SessionInitResponse:
		return h.verifyChallengeResponse(pkt.Signature)
	default:
		return errors.New("expected second challenge response")
	}
}

// buildChallenge generates a new challenge.
func (h *Handshaker) buildChallenge() (*SessionChallenge, error) {
	nonce := make([]byte, sessionNonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	h.challengeNonce = nonce
	return &SessionChallenge{ChallengeNonce: nonce}, nil
}

// sendPacket sends a packet.
func (h *Handshaker) sendPacket(pkt packet.ProtoPacket) error {
	return h.rw.WriteProtoPacket(pkt)
}

// sendChallengeResponse sends the challenge response.
func (h *Handshaker) sendChallengeResponse(challenge *SessionChallenge, nextChallenge *SessionChallenge) error {
	nonceLen := len(challenge.ChallengeNonce)
	if challenge == nil ||
		nonceLen < sessionNonceMin ||
		nonceLen > sessionNonceMax {
		return errors.New("packet challenge was nil or of an invalid length")
	}

	signedMsg, err := signature.NewSignedMessage(
		signature.ESignedMessageHash_HASH_SHA256,
		10,
		&SessionChallengeResponse{
			Challenge: challenge,
			Identity:  h.ident.Identity,
		},
		h.ident.GetPrivateKey(),
	)
	if err != nil {
		return err
	}

	return h.sendPacket(&SessionInitResponse{
		Signature: signedMsg,
		Challenge: nextChallenge,
	})
}

// verifyChallengeResponse checks the challenge response.
// Note: this is called on the server, so peerIdentity must be filled by this func.
func (h *Handshaker) verifyChallengeResponse(response *signature.SignedMessage) error {
	// parse message first
	resp := &SessionChallengeResponse{}
	if err := proto.Unmarshal(response.Message, resp); err != nil {
		return err
	}
	if resp.Challenge == nil {
		return errors.New("challenge response was empty")
	}
	if resp.Identity == nil || len(resp.Identity.CertAsn1) < 1 {
		return errors.New("peer identity in challenge response not given")
	}

	ident := identity.NewParsedIdentity(resp.Identity)
	chain, err := ident.ParseCertificates()
	if err != nil {
		return err
	}
	if err := chain.Validate(h.caCert); err != nil {
		return err
	}
	if bytes.Compare(resp.Challenge.ChallengeNonce, h.challengeNonce) != 0 {
		return fmt.Errorf(
			"challenge nonce did not match: %v != %v",
			resp.Challenge.ChallengeNonce,
			h.challengeNonce,
		)
	}

	h.challengeNonce = nil
	h.peerIdent = ident
	return nil
}
