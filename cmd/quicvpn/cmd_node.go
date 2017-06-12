package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/cmd/quicvpn/tls"
	"github.com/fuserobotics/quic-channel/discovery"
	"github.com/fuserobotics/quic-channel/node"
	"github.com/urfave/cli"
)

var nodeArgs struct {
	ListenPort int
	BcastPort  int
	PeerAddr   cli.StringSlice
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
			Name:        "bcast, b",
			Usage:       "Port to use for UDP discovery broadcasts.",
			Value:       2211,
			Destination: &nodeArgs.BcastPort,
		},
		cli.StringSliceFlag{
			Name:  "peer, p",
			Usage: "Peer to connect to after start.",
			Value: &nodeArgs.PeerAddr,
		},
	},
	Action: func(c *cli.Context) (retErr error) {
		defer func() { retErr = wrapReturnedError(retErr) }()

		tlsConfig, err := tls.LoadTLSConfig()
		if err != nil {
			return err
		}

		var discoveryWorkerConfigs []interface{}
		if nodeArgs.BcastPort != 0 {
			uconfs, err := discovery.GenerateUDPWorkerConfigs(nodeArgs.BcastPort, nodeArgs.ListenPort)
			if err != nil {
				return err
			}
			for _, conf := range uconfs {
				discoveryWorkerConfigs = append(discoveryWorkerConfigs, conf)
			}
		}

		exitCh := make(chan error, 1)
		n, err := node.NodeListenAddr(&node.NodeConfig{
			Context:          context.Background(),
			TLSConfig:        tlsConfig,
			Addr:             fmt.Sprintf(":%d", nodeArgs.ListenPort),
			DiscoveryConfigs: discoveryWorkerConfigs,
			ExitHandler: func(err error) {
				exitCh <- err
			},
		})
		if err != nil {
			return err
		}

		select {
		case err := <-exitCh:
			return err
		case <-time.After(time.Duration(1) * time.Second):
		}

		for _, peer := range nodeArgs.PeerAddr {
			go n.DialPeerAddr(peer)
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
