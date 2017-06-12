package discovery

import (
	"context"
)

// DiscoveryWorker discovers peers with a specific method.
type DiscoveryWorker interface {
	// DiscoverWorker processes discovering on the worker.
	DiscoverWorker(ctx context.Context) error
	// Description returns a human-readable description of this discovery worker.
	Description() string
}
