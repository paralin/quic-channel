package node

import (
	"context"
	"crypto/tls"
	"errors"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/circuit"
	"github.com/lucas-clemente/quic-go"
)

// NodeConfig is the configuration for a node.
type NodeConfig struct {
	// Context is the context for the node.
	Context context.Context
	// Addr is the address to listen on.
	Addr string
	// TLSConfig is the configuration for the node's TLS.
	TLSConfig *tls.Config
	// ExitHandler is called when the node exits.
	ExitHandler func(err error)
}

// Node manages sessions with peers.
type Node struct {
	config             NodeConfig
	listener           quic.Listener
	sessionHandler     *circuit.CircuitSessionManager
	childContext       context.Context
	childContextCancel context.CancelFunc
}

// NodeListenAddr builds a new node listening on a port with a configuration.
func NodeListenAddr(nc *NodeConfig) (nod *Node, reterr error) {
	if nc == nil || nc.TLSConfig == nil || nc.Addr == "" {
		return nil, errors.New("NodeConfig, TLSConfig, and Addr must be specified.")
	}

	// start listeners
	listener, err := quic.ListenAddr(nc.Addr, &quic.Config{TLSConfig: nc.TLSConfig})
	if err != nil {
		return nil, err
	}
	log.WithField("addr", nc.Addr).Debug("Listening")

	nod = &Node{
		listener: listener,
		config:   *nc,
	}
	nod.childContext, nod.childContextCancel = context.WithCancel(nc.Context)
	nod.sessionHandler = circuit.NewCircuitSessionManager(nod.childContext)
	go nod.listenPump()
	return nod, nil
}

// DialPeer attempts to open a session with a peer.
func (n *Node) DialPeerAddr(addr string) error {
	l := log.WithField("peer", addr)
	l.Debug("Dialing")
	session, err := quic.DialAddr(addr, &quic.Config{
		TLSConfig: n.config.TLSConfig,
	})
	if err != nil {
		l.WithError(err).Warn("Dial failed")
		return err
	}

	return n.handleSession(session, true)
}

// handleSession starts manging a incoming/outgoing session
func (n *Node) handleSession(sess quic.Session, initiator bool) error {
	_, err := n.sessionHandler.BuildCircuitSession(sess, initiator)

	if err != nil {
		log.WithError(err).Warn("Dropped session")
		sess.Close(err)
	}

	return err
}

// listenPump listens for incoming sessions.
func (n *Node) listenPump() (retErr error) {
	defer func() {
		n.childContextCancel()
	}()

	for {
		sess, err := n.listener.Accept()
		if err != nil {
			return err
		}

		n.handleSession(sess, false)
	}
}
