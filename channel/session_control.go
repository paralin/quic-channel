package channel

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/handshake"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/session"
)

// sessionControlState is the state for the session's control data.
type sessionControlState struct {
	context    context.Context
	config     *session.StreamHandlerConfig
	handshaker *handshake.Handshaker
	packets    chan packet.Packet

	initTimestamp       time.Time
	peerIdentity        *identity.ParsedIdentity
	localPrivateKey     *rsa.PrivateKey
	sessConfig          *ChannelSessionConfig
	expectChallengeResp bool

	activeHandlerMtx sync.Mutex
	activeHandler    *controlStreamHandler

	activePacketHandler func(pkt packet.Packet) error
}

// newSessionControlState builds a new control state.
func newSessionControlState(
	ctx context.Context,
	config *session.StreamHandlerConfig,
	sessConfig *ChannelSessionConfig,
) *sessionControlState {
	var s *sessionControlState
	s = &sessionControlState{
		context: ctx,
		config:  config,
		packets: make(chan packet.Packet, 5),
		handshaker: handshake.NewHandshaker(
			config.PacketRw,
			config.LocalIdentity,
			config.CaCert,
			func(peerIdentity *identity.ParsedIdentity) error {
				s.peerIdentity = peerIdentity
				return s.completeHandshake()
			},
			config.Session.IsInitiator(),
		),
		initTimestamp: time.Now(),
		sessConfig:    sessConfig,
	}
	s.activePacketHandler = s.handshaker.HandlePacket
	return s
}

// handleControl manages the control state of the session.
func (s *sessionControlState) handleControl() error {
	ctx := s.context
	l := s.config.Log
	if !s.config.Session.IsInitiator() {
		if err := s.handshaker.SendChallenge(); err != nil {
			return err
		}
	}
	for {
		var packet packet.Packet
		select {
		case <-ctx.Done():
			return context.Canceled
		case packet = <-s.packets:
		}

		l.Debugf("Got control packet: %#v", packet)
		if err := s.activePacketHandler(packet); err != nil {
			return err
		}
	}
}

// completeHandshake is called to complete the handshake sequence.
func (c *sessionControlState) completeHandshake() error {
	c.activePacketHandler = c.handleControlPacket
	c.handshaker = nil
	err := c.config.Session.GetManager().OnSessionReady(&session.SessionReadyDetails{
		Session:            c.config.Session,
		InitiatedTimestamp: c.initTimestamp,
		PeerIdentity:       c.peerIdentity,
	})
	if err != nil {
		return err
	}

	// c.config.Session.ResetInactivityTimeout(inactivityTimeout)

	pkh, err := c.peerIdentity.HashPublicKey()
	if err != nil {
		return err
	}
	hashId := pkh.MarshalHashIdentifier()
	c.config.Log = c.config.Log.WithField("peer", hashId)

	return nil
}

// handleControlPacket handles packets after the handshake is complete.
func (s *sessionControlState) handleControlPacket(packet packet.Packet) error {
	switch pkt := packet.(type) {
	default:
		s.config.Log.Warnf("Unhandled packet: %#v\n", pkt)
	}

	return nil
}

// sendPacket attempts to send a packet to the peer.
func (s *sessionControlState) sendPacket(packet packet.ProtoPacket) error {
	if s.activeHandler == nil {
		return errors.New("no control stream opened to send on")
	}

	return s.activeHandler.config.PacketRw.WriteProtoPacket(packet)
}
