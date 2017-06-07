package main

import (
	"context"
	"time"

	"github.com/fuserobotics/quic-channel/cmd/quicvpn/tls"
	"github.com/fuserobotics/quic-channel/node"
	"github.com/urfave/cli"
)

var nodeArgs struct {
	ListenAddr string
	PeerAddr   cli.StringSlice
}

// NodeCommand is the command to start a node.
var NodeCommand = cli.Command{
	Name:  "node",
	Usage: "Start the node.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:        "listen, l",
			Usage:       "Address to listen on.",
			Value:       ":2210",
			Destination: &nodeArgs.ListenAddr,
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

		exitCh := make(chan error, 1)
		n, err := node.NodeListenAddr(&node.NodeConfig{
			Context:   context.Background(),
			TLSConfig: tlsConfig,
			Addr:      nodeArgs.ListenAddr,
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

		return <-exitCh
	},
}
