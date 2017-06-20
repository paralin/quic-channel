package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/network"
	"github.com/golang/protobuf/proto"
	reuse "github.com/jbenet/go-reuseport"
)

// discoveryFrequency is the rate we emit discovery packets.
var discoveryFrequency time.Duration = time.Duration(10) * time.Second

// UDPDiscoveryWorker binds to a network interface and manages receiving and sending discovery packets.
type UDPDiscoveryWorker struct {
	discovery  *Discovery
	config     *UDPDiscoveryWorkerConfig
	pumpErrors chan error
	log        *log.Entry
	targetAddr *net.UDPAddr
}

// DiscoverWorker manages UDP discovery.
func (u *UDPDiscoveryWorker) DiscoverWorker(ctx context.Context) error {
	u.pumpErrors = make(chan error, 1)
	targetIp := u.config.Addr.IP.Mask(u.config.Addr.Mask)
	targetAddr := &net.UDPAddr{IP: targetIp, Port: u.config.Port}
	listenAddr := targetAddr
	u.targetAddr = targetAddr

	u.log = log.WithField("discovery", fmt.Sprintf("udp:%v", listenAddr.String()))
	uconn, err := reuse.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	defer uconn.Close()

	go u.readPump(uconn)

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case err := <-u.pumpErrors:
			return err
		}
	}
}

// timeoutError is returned when the read deadline is hit.
type timeoutError interface {
	// Timeout determines if the error is a timeout
	Timeout() bool
}

// readPump reads UDP discovery packets.
func (u *UDPDiscoveryWorker) readPump(conn net.PacketConn) (pumpErr error) {
	defer func() {
		if pumpErr != nil {
			u.pumpErrors <- pumpErr
		}
	}()

	buf := make([]byte, 10000)
	for {
		conn.SetReadDeadline(time.Now().Add(discoveryFrequency))
		nread, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if er, ok := err.(timeoutError); ok && er.Timeout() {
				if err := u.writeIdentifier(conn, u.targetAddr); err != nil {
					return err
				}
				continue
			} else {
				return err
			}
		}

		if nread == 0 {
			continue
		}

		// Read discovery packet
		disc := &DiscoveryUDPPacket{}
		l := u.log.WithField("addr", addr.String())
		err = proto.Unmarshal(buf[:nread], disc)

		var fromIP net.IP
		if err == nil {
			if disc.Port < 1000 {
				err = errors.New("Packet missing valid port info")
			}
		}
		if err == nil {
			uaddr, ok := addr.(*net.UDPAddr)
			if !ok {
				err = fmt.Errorf("Expected *net.UDPAddr receive but got %#v", addr)
			}
			fromIP = uaddr.IP
		}
		if err != nil {
			l.WithError(err).Warn("Got invalid discovery packet")
			continue
		}

		peerIdent := "unknown"
		if disc.Peer != nil {
			if disc.Peer.CompareTo(u.config.PeerIdentifier) {
				continue
			}
			peerIdent = disc.Peer.MarshalHashIdentifier()
		}

		connAddr := &net.UDPAddr{
			IP:   fromIP,
			Port: int(disc.Port),
		}

		u.log.
			WithField("addr", addr.String()).
			WithField("peer", peerIdent).
			WithField("to", connAddr.String()).
			Debug("Got discovery packet")
	}
}

// Description returns a human-readable description of the worker.
func (u *UDPDiscoveryWorker) Description() string {
	return fmt.Sprintf("UDP bcast on %s port %d", u.config.Addr.String(), u.config.Port)
}

// writeIdentifier writes the identification packet to the wire.
func (u *UDPDiscoveryWorker) writeIdentifier(conn net.PacketConn, target *net.UDPAddr) error {
	msg := &DiscoveryUDPPacket{
		Port: uint32(u.config.SessionPort),
		Peer: u.config.PeerIdentifier,
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	// u.log.Debug("Writing discovery packet")
	_, err = conn.WriteTo(data, target)
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
	// Identity is the local peer identifier
	PeerIdentifier *identity.PeerIdentifier
}

// GenerateUDPWorkerConfigs reads the list of network interfaces and generates UDP discovery workers.
// temporary implementation
func GenerateUDPWorkerConfigs(peerId *identity.PeerIdentifier, listenPort, sessionPort int) ([]*UDPDiscoveryWorkerConfig, error) {
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
			Addr:           bcastAddr,
			Interface:      inter,
			Port:           listenPort,
			SessionPort:    sessionPort,
			PeerIdentifier: peerId,
		})
	}
	return configs, nil
}
