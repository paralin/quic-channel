package identity

import (
	"bytes"
	"fmt"
	"net"
)

// IPv6AddrToPeer determines the CA cert hash prefix and the
// An IPv6 address is determined to be valid if it has the local cluster prefix.
func IPv6AddrToPeer(ip net.IP) (*PublicKeyPartialHash, *ClusterCertPartialHash, error) {
	// Compare local cluster prefix
	prefixLen := len(ipv6AddrPrefix)
	prefix := ip[:prefixLen]
	if bytes.Compare(prefix, ipv6AddrPrefix) != 0 {
		return nil, nil, fmt.Errorf("Cluster prefix %s != expected %s", net.IP(prefix).String(), ipv6AddrPrefix.String())
	}

	var clusterHash ClusterCertPartialHash
	copy(clusterHash[:], ip[prefixLen:])

	var publicKeyHash PublicKeyPartialHash
	copy(publicKeyHash[:], ip[6:])

	return &publicKeyHash, &clusterHash, nil
}
