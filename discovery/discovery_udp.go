package discovery

import (
	"context"
	"fmt"
	"net"

	"github.com/fuserobotics/quic-channel/network"
	"github.com/golang/protobuf/proto"
)

// UDPDiscoveryWorker binds to a network interface and manages receiving and sending discovery packets.
type UDPDiscoveryWorker struct {
	discovery *Discovery
	config    *UDPDiscoveryWorkerConfig
}

// DiscoverWorker manages UDP discovery.
func (u *UDPDiscoveryWorker) DiscoverWorker(ctx context.Context) error {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   u.config.Addr.IP,
		Port: u.config.Port,
	})
	if err != nil {
		return err
	}
	defer uconn.Close()

	targetAddr := u.config.Addr.IP.Mask(u.config.Addr.Mask)
	_ = targetAddr
	return nil
}

// Description returns a human-readable description of the worker.
func (u *UDPDiscoveryWorker) Description() string {
	return fmt.Sprintf("UDP bcast on %s port %d", u.config.Addr.String(), u.config.Port)
}

// writeIdentifier writes the identification packet to the wire.
func (u *UDPDiscoveryWorker) writeIdentifier(conn *net.UDPConn, target *net.UDPAddr) error {
	msg := &DiscoveryUDPPacket{}

	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = conn.WriteToUDP(data, target)
	return err
}

// UDPDiscoveryWorkerConfig contains details used to configure the worker.
type UDPDiscoveryWorkerConfig struct {
	// Interface is the network interface to discover over.
	Interface *network.NetworkInterface
	// Addr is the address on the interface to use.
	Addr *net.IPNet
	// Port is the port to listen on and broadcast to.
	Port int
	// SessionPort is the port the session listener is on
	SessionPort int
}

// GenerateUDPWorkerConfigs reads the list of network interfaces and generates UDP discovery workers.
// temporary implementation
func GenerateUDPWorkerConfigs(listenPort, sessionPort int) ([]*UDPDiscoveryWorkerConfig, error) {
	inters, err := network.ListNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	var configs []*UDPDiscoveryWorkerConfig
	for _, inter := range inters {
		bcastAddr := inter.BroadcastAddr()
		if bcastAddr == nil {
			continue
		}
		configs = append(configs, &UDPDiscoveryWorkerConfig{
			Addr:        bcastAddr,
			Interface:   inter,
			Port:        listenPort,
			SessionPort: sessionPort,
		})
	}
	return configs, nil
}
