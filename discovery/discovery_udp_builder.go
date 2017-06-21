package discovery

import (
	"context"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/network"
)

// interfaceScanInterval is the time between interfaces
var interfaceScanInterval = time.Duration(10) * time.Second

// UDPDiscoveryWorkerBuilder monitors local interfaces and starts discovery workers.
type UDPDiscoveryWorkerBuilder struct {
	config  *UDPDiscoveryWorkerBuilderConfig
	workers map[uint32]*UDPDiscoveryWorker
	failed  chan uint32
	eventCh chan<- *DiscoveryEvent
}

func (u *UDPDiscoveryWorkerBuilder) scanInterfaces(ctx context.Context) error {
	inters, err := network.ListNetworkInterfaces()
	if err != nil {
		return err
	}

	for _, inter := range inters {
		ident := inter.Identifier()
		if _, ok := u.workers[ident]; ok {
			continue
		}
		bcastAddr := inter.BroadcastAddr()
		if bcastAddr == nil {
			continue
		}
		worker := &UDPDiscoveryWorker{
			config: &UDPDiscoveryWorkerConfig{
				Addr:           bcastAddr,
				Interface:      inter,
				Port:           u.config.Port,
				SessionPort:    u.config.SessionPort,
				PeerIdentifier: u.config.PeerIdentifier,
			},
			eventCh: u.eventCh,
		}
		u.workers[ident] = worker
		go func(ctx context.Context, wrk *UDPDiscoveryWorker) {
			log.Debugf("Starting UDP worker: %s", wrk.Description())
			err := wrk.DiscoverWorker(ctx)
			if err != nil {
				log.WithError(err).Warn("UDP listener exited")
			}
			select {
			case <-ctx.Done():
			case u.failed <- ident:
			}
		}(ctx, worker)
	}

	return nil
}

// DiscoverWorker manages UDP discovery.
func (u *UDPDiscoveryWorkerBuilder) DiscoverWorker(ctx context.Context) error {
	u.workers = make(map[uint32]*UDPDiscoveryWorker)
	u.failed = make(chan uint32)
	rescanTimer := time.NewTimer(interfaceScanInterval)

	for {
		if err := u.scanInterfaces(ctx); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return context.Canceled
		case <-rescanTimer.C:
			rescanTimer.Reset(interfaceScanInterval)
		case id := <-u.failed:
			delete(u.workers, id)
		}
	}
}

// Description returns a human-readable description of the worker.
func (u *UDPDiscoveryWorkerBuilder) Description() string {
	return fmt.Sprintf("UDP bcast builder, all interfaces port %d", u.config.Port)
}

// UDPDiscoveryWorkerBuilderConfig configures a UDPDiscoveryWorkerBuilder
type UDPDiscoveryWorkerBuilderConfig struct {
	// Port is the port to listen on and broadcast to.
	Port int
	// SessionPort is the port the session listener is on
	SessionPort int
	// Identity is the local peer identifier
	PeerIdentifier *identity.PeerIdentifier
}

// BuildWorker returns the worker.
func (u *UDPDiscoveryWorkerBuilderConfig) BuildWorker(eventCh chan<- *DiscoveryEvent) (DiscoveryWorker, error) {
	return &UDPDiscoveryWorkerBuilder{
		config:  u,
		eventCh: eventCh,
	}, nil
}
