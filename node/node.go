package node

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/circuit"
	"github.com/fuserobotics/quic-channel/discovery"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
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
	// DiscoveryConfigs are discovery worker configurations.
	DiscoveryConfigs []interface{}
	// ExitHandler is called when the node exits.
	ExitHandler func(err error)
}

// Node manages sessions with peers.
type Node struct {
	config             NodeConfig
	listener           quic.Listener
	childContext       context.Context
	childContextCancel context.CancelFunc
	sesssionHandler    nodeSessionHandler
	discovery          *discovery.Discovery

	// peers, keyed by sha256 of public key
	peers map[identity.PublicKeyHash]*peer.Peer
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
		discovery: discovery.NewDiscovery(discovery.DiscoveryConfig{
			Context:   nc.Context,
			TLSConfig: nc.TLSConfig,
		}),
	}
	nod.sesssionHandler.Node = nod
	nod.childContext, nod.childContextCancel = context.WithCancel(nc.Context)
	go nod.listenPump()
	for _, conf := range nod.config.DiscoveryConfigs {
		if err := nod.discovery.AddDiscoveryWorker(conf); err != nil {
			log.WithError(err).Warn("Unable to start discovery worker")
		}
	}
	return nod, nil
}

// DialPeerAddr attempts to open a session with a peer.
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

	return n.HandleSession(session, true)
}

// DialPeer attempts to open a session with a peer.
func (n *Node) DialPeer(conn net.PacketConn, remoteAddr net.Addr, host string) error {
	l := log.WithField("addr", remoteAddr.String())
	session, err := quic.Dial(conn, remoteAddr, host, &quic.Config{
		TLSConfig: n.config.TLSConfig,
	})
	if err != nil {
		l.WithError(err).Warn("Dial with PacketConn failed")
		return err
	}

	return n.HandleSession(session, true)
}

// HandleSession starts manging a incoming/outgoing session
func (n *Node) HandleSession(sess quic.Session, initiator bool) error {
	_, err := circuit.BuildCircuitSession(n.childContext, sess, initiator, &n.sesssionHandler)

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

		n.HandleSession(sess, false)
	}
}
