package discovery

import (
	"context"
)

// DiscoveryWorkerConfig configures a DiscoveryWorker
type DiscoveryWorkerConfig interface {
	// BuildWorker yields a worker from the config.
	BuildWorker(ch chan<- *DiscoveryEvent) (DiscoveryWorker, error)
}

// DiscoveryWorker discovers peers with a specific method.
type DiscoveryWorker interface {
	// DiscoverWorker processes discovering on the worker.
	DiscoverWorker(ctx context.Context) error
	// Description returns a human-readable description of this discovery worker.
	Description() string
}
