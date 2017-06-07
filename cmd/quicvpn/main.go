package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/cmd/quicvpn/tls"
	"github.com/urfave/cli"
)

func wrapReturnedError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*cli.ExitError); ok {
		return err
	}
	return cli.NewExitError(err.Error(), 1)
}

func main() {
	log.SetLevel(log.DebugLevel)

	app := cli.NewApp()
	app.Name = "quicchannel"
	app.Usage = "Mesh networking with QUIC channels."
	app.Author = "Christian Stewart <christian@paral.in>"
	app.Commands = []cli.Command{
		NodeCommand,
		GenCertCommand,
	}
	app.Flags = append(app.Flags, tls.TlsFlags...)
	app.Run(os.Args)
}
