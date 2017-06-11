package circuit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/session"
)

// sessionControlState is the state for the session's control data.
type sessionControlState struct {
	context       context.Context
	config        *session.StreamHandlerConfig
	packets       chan packet.Packet
	initTimestamp time.Time

	activeHandlerMtx sync.Mutex
	activeHandler    *controlStreamHandler
}

// handleControl manages the control state of the session.
func (s *sessionControlState) handleControl() error {
	ctx := s.context
	l := s.config.Log
	keepAliveTimer := time.NewTimer(keepAliveFrequency)
	if !s.config.Session.IsInitiator() {
		keepAliveTimer.Stop()
	}
	for {
		var packet packet.Packet
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-keepAliveTimer.C:
			if err := s.sendKeepAlive(); err != nil {
				return err
			}
			keepAliveTimer.Reset(keepAliveFrequency)
			continue
		case packet = <-s.packets:
		}

		if _, ok := packet.(*ControlKeepAlive); !ok {
			l.Debugf("Got control packet: %#v", packet)
		}
		if s.initTimestamp.IsZero() {
			switch pkt := packet.(type) {
			case *ControlSessionInit:
				s.initTimestamp = time.Unix(0, int64(pkt.Timestamp))
				l.WithField("timestamp", s.initTimestamp.String()).Debug("Session initialized")
				err := s.config.Session.GetManager().OnSessionReady(&session.SessionReadyDetails{InitiatedTimestamp: s.initTimestamp})
				if err != nil {
					return err
				}
				s.config.Session.ResetInactivityTimeout(inactivityTimeout)
				keepAliveTimer.Reset(keepAliveFrequency)
				continue
			default:
				return errors.New("Received control packet before session init completed.")
			}
		}

		switch pkt := packet.(type) {
		case *ControlKeepAlive:
			s.config.Session.ResetInactivityTimeout(inactivityTimeout)
			continue
		default:
			l.Warnf("Unhandled packet: %#v\n", pkt)
		}
	}
}

// sendKeepAlive transmits a keep alive message to the stream.
func (c *sessionControlState) sendKeepAlive() error {
	c.activeHandlerMtx.Lock()
	defer c.activeHandlerMtx.Unlock()

	if c.activeHandler != nil {
		return c.activeHandler.config.PacketRw.WritePacket(&ControlKeepAlive{})
	}
	return nil
}
