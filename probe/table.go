package probe

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/peer"
	"github.com/fuserobotics/quic-channel/route"
)

// ProbeTableMarker marks the probe table in the context.
var ProbeTableMarker = new(struct{ probeTableMarker int })

// probeLookup is an active lookup request on the table.
type probeLookup struct {
	skipPeer *identity.ParsedIdentity
	resultCh chan<- *route.ParsedRoute
}

// ProbeTable manages route probes.
type ProbeTable struct {
	// ctx is the context
	ctx context.Context
	// tableMtx locks when adding new probes
	tableMtx sync.Mutex
	// table correlates incoming peers + the interface they were seen on with probes
	table map[peerInterfaceHash]map[route.RouteSegmentsSha1]*route.ParsedRoute
	// ca certificate
	caCert *x509.Certificate
	// routeProbeLookupCh includes new route probes that must be processed
	routeProbeLookupCh chan *probeLookup
	// purgePeerInterfaceCh includes peer interfaces that must be purged.
	purgePeerInterfaceCh chan peerInterfaceHash
}

// NewProbeTable builds a new probe table.
func NewProbeTable(
	ctx context.Context,
	caCert *x509.Certificate,
) *ProbeTable {
	r := &ProbeTable{
		ctx:                  ctx,
		caCert:               caCert,
		table:                make(map[peerInterfaceHash]map[route.RouteSegmentsSha1]*route.ParsedRoute),
		routeProbeLookupCh:   make(chan *probeLookup),
		purgePeerInterfaceCh: make(chan peerInterfaceHash),
	}

	return r
}

// ManageProbeTable is a goroutine to manage the table.
func (p *ProbeTable) ManageProbeTable() error {
	purgeTimer := time.NewTimer(time.Duration(10) * time.Second)
	purgeTimer.Stop()

	for {
		var lkps []*probeLookup
		var err error

		select {
		case <-p.ctx.Done():
			return context.Canceled
		case <-purgeTimer.C:
		case lkp := <-p.routeProbeLookupCh:
			lkps = append(lkps, lkp)
		case hash := <-p.purgePeerInterfaceCh:
			p.tableMtx.Lock()
			delete(p.table, hash)
			p.tableMtx.Unlock()
			continue
		}

		purgeTimer.Stop()
		if lkps, err = p.flushLookups(lkps); err != nil {
			return err
		}

		p.tableMtx.Lock()
		earliestExpr, err := p.sweep(lkps)
		p.tableMtx.Unlock()
		if err != nil {
			return err
		}

		if earliestExpr > 0 {
			purgeTimer.Reset(earliestExpr)
		}
	}
}

// PurgePeerInterface removes a peer interface from the table.
// Note: blocks until the table accepts the modification.
func (p *ProbeTable) PurgePeerInterface(peer *peer.Peer, interfaceID uint32) {
	hash := hashPeerAndInterface(peer, interfaceID)
	select {
	case <-p.ctx.Done():
		return
	case p.purgePeerInterfaceCh <- hash:
	}
}

// AddProbe adds a probe coming from a peer interface to the table, and returns if it's a duplicate.
func (p *ProbeTable) AddProbe(peer *peer.Peer, interfaceID uint32, probe *route.ParsedRoute) bool {
	if probe.TimeTillExpiration() <= 0 {
		return false
	}
	probe.SetIncomingInterface(interfaceID)

	peerInterHash := hashPeerAndInterface(peer, interfaceID)
	segmentsHash := probe.HashRouteSegmentsSha1()

	p.tableMtx.Lock()
	defer p.tableMtx.Unlock()

	peerInterTable, ok := p.table[peerInterHash]
	if !ok {
		peerInterTable = make(map[route.RouteSegmentsSha1]*route.ParsedRoute)
		p.table[peerInterHash] = peerInterTable
	}

	existingProbe := peerInterTable[segmentsHash]
	if existingProbe != nil {
		if existingProbe.TimeTillExpiration() < 0 {
			existingProbe = nil
		}
	}
	if existingProbe == nil {
		peerInterTable[segmentsHash] = probe
	}
	return existingProbe != nil
}

// LookupProbes returns all active route probes not including a peer.
func (p *ProbeTable) LookupProbes(excludeIdent *identity.ParsedIdentity) ([]*route.ParsedRoute, error) {
	resultCh := make(chan *route.ParsedRoute, 10)
	var result []*route.ParsedRoute
	lookup := probeLookup{
		resultCh: resultCh,
		skipPeer: excludeIdent,
	}

	select {
	case <-p.ctx.Done():
		return nil, context.Canceled
	case p.routeProbeLookupCh <- &lookup:
	}

ResultLoop:
	for {
		select {
		case <-p.ctx.Done():
			return nil, context.Canceled
		case route, ok := <-resultCh:
			if !ok {
				break ResultLoop
			}
			result = append(result, route)
		}
	}

	return result, nil
}

// flushLookups gets all currently pending lookups.
func (p *ProbeTable) flushLookups(appendTo []*probeLookup) ([]*probeLookup, error) {
	for {
		select {
		case <-p.ctx.Done():
			return nil, context.Canceled
		case lookup := <-p.routeProbeLookupCh:
			appendTo = append(appendTo, lookup)
		default:
			return appendTo, nil
		}
	}
}

// sweep sweeps the table for lookup entries and returns the least time till next expiration
func (p *ProbeTable) sweep(lookups []*probeLookup) (time.Duration, error) {
	hasLookups := len(lookups) != 0
	earliestExpr := time.Duration(0)
	for tableKey, segMap := range p.table {
		for segHash, rt := range segMap {
			ttx := rt.TimeTillExpiration()
			if ttx <= 0 {
				delete(segMap, segHash)
				if len(segMap) == 0 {
					delete(p.table, tableKey)
				}
				continue
			}

			if ttx < earliestExpr {
				earliestExpr = ttx
			}

			if !hasLookups {
				continue
			}

			hops, err := rt.DecodeHops(p.caCert)
			if err != nil {
				continue
			}

		LookupLoop:
			for _, lkp := range lookups {
				if lkp.skipPeer != nil {
					for _, hop := range hops {
						if hop.GetIdentity().MatchesIdentity(lkp.skipPeer) {
							continue LookupLoop
						}
					}
				}

				select {
				case <-p.ctx.Done():
					return earliestExpr, context.Canceled
				case lkp.resultCh <- rt:
				}
			}
		}
	}

	for _, lkp := range lookups {
		close(lkp.resultCh)
	}

	return earliestExpr, nil
}
