// +build use_kcp

package node

import (
	"crypto/tls"
	"time"

	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/netproto/kcp"
)

// defaultNetworkingProtocol returns the default protocol.
func defaultNetworkingProtocol(tlsConf *tls.Config) netproto.Protocol {
	return kcp.NewKCP(nil, nil, time.Duration(0))
}
