package discovery

import (
	"context"
	"crypto/tls"

	// "github.com/fuserobotics/quic-channel/identity"
	log "github.com/Sirupsen/logrus"
	"github.com/fuserobotics/quic-channel/peer"
)

// Discovery manages building sessions with peers over local interfaces.
type Discovery struct {
	config     DiscoveryConfig
	pumpErrors chan error
	peerDb     *peer.PeerDatabase
	eventCh    chan *DiscoveryEvent
}

// DiscoveryConfig is the information used to construct a Discovery.
type DiscoveryConfig struct {
	// Context, when canceled will terminate the Discovery.
	Context context.Context
	// TLSConfig is the configuration for the local TLS.
	TLSConfig *tls.Config
	// EventHandlers get calls when events occur.
	EventHandlers []DiscoveryEventHandler
	// PeerDb is the peer database.
	PeerDb *peer.PeerDatabase
}

// DiscoveryEventHandler has callbacks for events in the discovery.
type DiscoveryEventHandler interface {
	// OnPeerEvent is called when a peer has a new discovery event.
	OnPeerEvent(event *DiscoveryEvent)
}

// NewDiscovery builds a new Discovery.
func NewDiscovery(config DiscoveryConfig) *Discovery {
	return &Discovery{
		config:     config,
		pumpErrors: make(chan error, 2),
		peerDb:     config.PeerDb,
		eventCh:    make(chan *DiscoveryEvent, 10),
	}
}

// ManageDiscovery is the routine to manage the discovery.
func (d *Discovery) ManageDiscovery() (retErr error) {
	for {
		select {
		case <-d.config.Context.Done():
			return context.Canceled
		case eve := <-d.eventCh:
			for _, handler := range d.config.EventHandlers {
				handler.OnPeerEvent(eve)
			}
		}
	}
}

// AddDiscoveryWorker adds and starts a worker given a worker config.
func (d *Discovery) AddDiscoveryWorker(conf DiscoveryWorkerConfig) error {
	worker, err := conf.BuildWorker(d.eventCh)
	if err != nil {
		return err
	}

	if worker != nil {
		go func() {
			log.Debugf("Starting discovery worker: %s", worker.Description())
			err := worker.DiscoverWorker(d.config.Context)
			if err != nil {
				log.WithError(err).Warn("Discovery worker failed")
			} else {
				log.Debug("Discovery worker exited")
			}
		}()
	}

	return nil
}

// startPump starts a goroutine that will fail the Discovery if errored.
func (d *Discovery) startPump(pump func() error) {
	go func() {
		err := pump()
		if err != nil {
			select {
			case d.pumpErrors <- err:
			default:
			}
		}
	}()
}
