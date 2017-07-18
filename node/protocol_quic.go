// +build !use_kcp

package node

import (
	"crypto/tls"

	"github.com/fuserobotics/netproto"
	"github.com/fuserobotics/netproto/quic"
	proto "github.com/lucas-clemente/quic-go"
)

// defaultNetworkingProtocol returns the default protocol.
func defaultNetworkingProtocol(tlsConf *tls.Config) netproto.Protocol {
	return quic.NewQuic(&proto.Config{}, tlsConf)
}
