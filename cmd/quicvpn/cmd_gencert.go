package main

import (
	"github.com/fuserobotics/quic-channel/cmd/quicvpn/tls"
	"github.com/urfave/cli"
)

// GenCertCommand generates the device certificate.
var GenCertCommand = cli.Command{
	Name:  "gencert",
	Usage: "Generate the certificate and key.",
	Action: func(c *cli.Context) (retErr error) {
		defer func() { retErr = wrapReturnedError(retErr) }()
		return tls.GenerateTLSCert()
	},
}
