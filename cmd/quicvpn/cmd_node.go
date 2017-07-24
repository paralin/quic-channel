package main

import (
	"context"
	"os"
	"os/signal"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/cmd/quicvpn/tls"
	"github.com/fuserobotics/quic-channel/discovery"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/node"
	"github.com/urfave/cli"
)

var nodeArgs struct {
	ListenPort  int
	BcastPort   int
	PeerAddr    cli.StringSlice
	CircuitPeer cli.StringSlice
}

// NodeCommand is the command to start a node.
var NodeCommand = cli.Command{
	Name:  "node",
	Usage: "Start the node.",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:        "listen, l",
			Usage:       "Port to listen for sessions.",
			Value:       2210,
			Destination: &nodeArgs.ListenPort,
		},
		cli.IntFlag{
			Name:  "bcast, b",
			Usage: "Port to use for UDP discovery broadcasts.",
			// Value:       2211, // do not listen on default for now
			Destination: &nodeArgs.BcastPort,
		},
		cli.StringSliceFlag{
			Name:  "peer, p",
			Usage: "Peer to connect to after start.",
			Value: &nodeArgs.PeerAddr,
		},
		cli.StringSliceFlag{
			Name:  "circuit",
			Usage: "Peer IDs to build circuits to after start.",
			Value: &nodeArgs.CircuitPeer,
		},
	},
	Action: func(c *cli.Context) (retErr error) {
		defer func() { retErr = wrapReturnedError(retErr) }()

		tlsConfig, caCert, err := tls.LoadTLSConfig()
		if err != nil {
			return err
		}

		exitCh := make(chan error, 1)
		n, err := node.BuildNode(&node.NodeConfig{
			Context:   context.Background(),
			TLSConfig: tlsConfig,
			CaCert:    caCert,
			ExitHandler: func(err error) {
				exitCh <- err
			},
		})
		if err != nil {
			return err
		}

		var discoveryWorkerConfigs []discovery.DiscoveryWorkerConfig
		if nodeArgs.BcastPort != 0 {
			ppid, err := n.GetLocalIdentity().ToPartialPeerIdentifier()
			if err != nil {
				return err
			}
			discoveryWorkerConfigs = append(discoveryWorkerConfigs, &discovery.UDPDiscoveryWorkerBuilderConfig{
				PeerIdentifier: ppid,
				Port:           nodeArgs.BcastPort,
				SessionPort:    nodeArgs.ListenPort,
			})
		}

		err = n.ListenAddr(&node.NodeListenConfig{
			Port:             nodeArgs.ListenPort,
			DiscoveryConfigs: discoveryWorkerConfigs,
		})
		if err != nil {
			return err
		}

		for _, peer := range nodeArgs.PeerAddr {
			go n.DialPeer(peer)
		}

		for _, peer := range nodeArgs.CircuitPeer {
			peerId, err := identity.BuildPeerIdentifier(peer)
			if err != nil {
				log.WithField("peer", peer).WithError(err).Warn("Skipping invalid peer identifier from cli")
			}

			err = n.BuildCircuit(peerId)
			if err != nil {
				log.WithField("peer", peer).WithError(err).Warn("Error starting circuit builder")
			}
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)

		select {
		case err := <-exitCh:
			return err
		case <-sigCh:
			log.Info("Shutting down...")
			// TODO: graceful shutdown
			return nil
		}
	},
}
