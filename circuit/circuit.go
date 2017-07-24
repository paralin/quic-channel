package circuit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	// "net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/netproto"
	npq "github.com/fuserobotics/netproto/quic"
	"github.com/fuserobotics/quic-channel/channel"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/network"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
	"github.com/fuserobotics/quic-channel/session"
	"github.com/lucas-clemente/quic-go"
)

// Circuit manages state for a multi-hop connection.
type Circuit struct {
	BoundPacketConn network.BoundPacketConn
	ctx             context.Context
	ctxCancel       context.CancelFunc
	initiator       bool
	log             *log.Entry
	sessionHandler  circuitSessionHandler

	peer          *peer.Peer
	routeProbe    *route.ParsedRoute
	outgoingInter *network.NetworkInterface
	tlsConfig     *tls.Config
	localIdentity *identity.ParsedIdentity
	caCert        *x509.Certificate
	builtHandler  CircuitBuiltHandler

	session netproto.Session

	sessionMtx sync.Mutex
	// sessionBuiltCallbacks []chan *ChannelSession // TODO:
}

// newCircuit builds the base circuit object.
func newCircuit(
	ctx context.Context,
	localTLSConfig *tls.Config,
	localIdentity *identity.ParsedIdentity,
	caCert *x509.Certificate,
	peer *peer.Peer,
	outgoingInter *network.NetworkInterface,
	packetConn network.BoundPacketConn,
	builtHandler CircuitBuiltHandler,
	// If we are the initiator, then we sent the Establish message.
	initiator bool,
	log *log.Entry,
	routeProbe *route.ParsedRoute,
) *Circuit {
	c := &Circuit{
		BoundPacketConn: packetConn,
		log:             log,
		initiator:       initiator,
		peer:            peer,
		outgoingInter:   outgoingInter,
		tlsConfig:       localTLSConfig,
		localIdentity:   localIdentity,
		caCert:          caCert,
		builtHandler:    builtHandler,
		routeProbe:      routeProbe,
	}

	if !peer.IsIdentified() {
		panic("peer must be identified to build circuit")
	}

	c.ctx, c.ctxCancel = context.WithCancel(ctx)
	c.sessionHandler.Circuit = c

	return c
}

// GetOutgoingInterface returns the interface this circuit is attached to.
func (c *Circuit) GetOutgoingInterface() *network.NetworkInterface {
	return c.outgoingInter
}

// GetRoute returns the route.
func (c *Circuit) GetRoute() *route.ParsedRoute {
	return c.routeProbe
}

// GetPeer gets the circuit peer.
func (c *Circuit) GetPeer() *peer.Peer {
	return c.peer
}

// ManageCircuit is a goroutine to manage state for the circuit.
func (c *Circuit) ManageCircuit() (retErr error) {
	defer func() {
		if retErr != nil {
			c.log.WithError(retErr).Error("Circuit exited with error")
		} else {
			c.log.Debug("Circuit exited")
		}
	}()

	if err := c.establishSession(); err != nil {
		return err
	}
	c.log.Debug("Circuit channel session established")
	defer c.session.Close()

	channelSess, err := channel.BuildChannelSession(
		c.ctx,
		c.session,
		&c.sessionHandler,
		c.localIdentity,
		c.caCert,
		c.tlsConfig,
		&channel.ChannelSessionConfig{
			ExpectedPeerIdentity: c.peer.GetIdentity(),
		},
	)
	if err != nil {
		return err
	}

	retErrCh := make(chan error, 1)
	channelSess.AddCloseCallback(func(s *session.Session, err error) {
		retErrCh <- err
	})

	select {
	case <-c.ctx.Done():
		return context.Canceled
	case err := <-retErrCh:
		return err
	}
}

// establishSession dials or listens for the incoming session.
func (c *Circuit) establishSession() error {
	var sess netproto.Session
	var err error

	if c.initiator {
		c.log.Debug("Establishing session by accepting peer")
		sess, err = c.acceptPeer()
	} else {
		c.log.Debug("Establishing session by dialing peer")
		sess, err = c.dialPeer()
	}

	if err != nil {
		c.log.WithError(err).Warn("Session establish failed")
	}

	c.session = sess
	return err
}

// buildProtocol constructs the protocol for the session.
func (c *Circuit) buildProtocol() netproto.Protocol {
	return npq.NewQuic(
		&quic.Config{
			RequestConnectionIDTruncation: true,
			KeepAlive:                     true,
		},
		c.tlsConfig,
	)
}

// acceptPeer accepts a incoming peer quic session.
func (c *Circuit) acceptPeer() (netproto.Session, error) {
	listener, err := c.buildProtocol().ListenWithConn(c.BoundPacketConn)
	if err != nil {
		return nil, err
	}

	return listener.AcceptSession()
}

// dialPeer starts dialing over the built circuit.
// note: this is a blocking function.
func (c *Circuit) dialPeer() (netproto.Session, error) {
	peerName := c.peer.GetIdentifier()
	sni := fmt.Sprintf("%s:%d", peerName, 1) // TODO: determine the proper SNI
	return c.buildProtocol().
		DialWithConn(c.BoundPacketConn, c.BoundPacketConn.RemoteAddr(), sni)
}
