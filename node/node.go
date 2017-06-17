package node

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
	// TLSConfig is the configuration for the node's TLS.
	TLSConfig *tls.Config
	// CaCert is the certificate for the CA.
	CaCert *x509.Certificate
	// ExitHandler is called when the node exits.
	ExitHandler func(err error)
}

// NodeListenConfig is the the config for listening on a port and discovery.
// Note: without setting this up, we can run in connect-out mode only.
type NodeListenConfig struct {
	// Port is the port to listen on.
	Port int
	// DiscoveryConfigs are discovery worker configurations.
	DiscoveryConfigs []interface{}
}

// Node manages sessions with peers.
type Node struct {
	config             NodeConfig
	listener           quic.Listener
	childContext       context.Context
	childContextCancel context.CancelFunc
	sessionHandler     nodeSessionHandler
	discovery          *discovery.Discovery
	localIdentity      *identity.ParsedIdentity
	peerDb             *peer.PeerDatabase
}

// ListenAddr tries to start listening on a port and starts discovery.
func (n *Node) ListenAddr(lc *NodeListenConfig) error {
	if n.listener != nil {
		return errors.New("Can only call ListenAddr once!")
	}

	// start listeners
	listener, err := quic.ListenAddr(fmt.Sprintf(":%d", lc.Port), &quic.Config{TLSConfig: n.config.TLSConfig})
	if err != nil {
		return err
	}
	log.WithField("port", lc.Port).Debug("Listening")
	n.listener = listener
	go n.listenPump()

	n.discovery = discovery.NewDiscovery(discovery.DiscoveryConfig{
		Context:   n.childContext,
		TLSConfig: n.config.TLSConfig,
		PeerDb:    n.peerDb,
	})
	for _, conf := range lc.DiscoveryConfigs {
		if err := n.discovery.AddDiscoveryWorker(conf); err != nil {
			log.WithError(err).Warn("Unable to start discovery worker")
		}
	}

	return nil
}

// BuildNode builds a new node with a configuration.
func BuildNode(nc *NodeConfig) (nod *Node, reterr error) {
	if nc == nil || nc.TLSConfig == nil {
		return nil, errors.New("NodeConfig, TLSConfig must be specified.")
	}

	nod = &Node{config: *nc, peerDb: peer.NewPeerDatabase()}
	nod.sessionHandler.Node = nod
	nod.childContext, nod.childContextCancel = context.WithCancel(nc.Context)

	// build identity
	var err error
	if len(nc.TLSConfig.Certificates) != 1 {
		return nil, errors.New("TLSConfig.Certificates must have a single certificate chain.")
	}

	cert := nc.TLSConfig.Certificates[0]
	rsaPrivate, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Expected rsa private key, got: %#v", cert.PrivateKey)
	}

	chain := make(identity.CertificateChain, len(cert.Certificate))
	for i, certb := range cert.Certificate {
		chain[i], err = x509.ParseCertificate(certb)
		if err != nil {
			return nil, err
		}
	}
	if err := chain.Validate(nc.CaCert); err != nil {
		return nil, err
	}

	nod.localIdentity, err = identity.NewParsedIdentityFromChain(chain)
	if err != nil {
		return nil, err
	}
	if err := nod.localIdentity.SetPrivateKey(rsaPrivate); err != nil {
		return nil, err
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
	_, err := circuit.BuildCircuitSession(
		n.childContext,
		sess,
		initiator,
		&n.sessionHandler,
		n.localIdentity,
		n.config.CaCert,
	)

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
