package route

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/signature"
	"github.com/fuserobotics/quic-channel/timestamp"
	"github.com/golang/protobuf/proto"
)

// ParsedRoute is a fully parsed route.
type ParsedRoute struct {
	*Route

	routeHops          RouteHops
	routeHopIdentities RouteHopIdentities
}

// NewParsedRoute builds a new ParsedRoute.
func NewParsedRoute() *ParsedRoute {
	route := &Route{}
	return &ParsedRoute{Route: route}
}

// BuildParsedRoute builds a new ParsedRoute from a Route.
func BuildParsedRoute(route *Route) *ParsedRoute {
	return &ParsedRoute{Route: route}
}

// Reset resets the route.
func (p *ParsedRoute) Reset() {
	p.routeHops = nil
	p.routeHopIdentities = nil
	p.Route.Reset()
}

// Verify attempts to parse and verify the entire route.
func (p *ParsedRoute) Verify(ca *x509.Certificate) error {
	hops, hopIdentities, err := p.DecodeHops(ca)
	if err != nil {
		return err
	}

	if p.Route.Destination == nil {
		return errors.New("Route destination cannot be nil.")
	}
	if err := p.Route.Destination.Verify(); err != nil {
		return err
	}

	if err := hops.Verify(ca, p.Hop, hopIdentities); err != nil {
		return err
	}

	return nil
}

// PopHop removes the last hop in the route.
func (p *ParsedRoute) PopHop() {
	if len(p.Hop) == 0 {
		return
	}

	if p.routeHops != nil {
		p.routeHops = p.routeHops[:len(p.routeHops)-1]
	}
	if p.routeHopIdentities != nil {
		p.routeHopIdentities = p.routeHopIdentities[:len(p.routeHopIdentities)-1]
	}
	p.Route.PopHop()
}

// DecodeHops returns the parsed list of hops and caches it for future use.
func (p *ParsedRoute) DecodeHops(ca *x509.Certificate) (RouteHops, RouteHopIdentities, error) {
	if p.routeHops != nil {
		return p.routeHops, p.routeHopIdentities, nil
	}

	hops, idents, err := p.Route.DecodeHops(ca)
	if err != nil {
		return nil, nil, err
	}

	if hops == nil {
		hops = RouteHops{}
	}
	if idents == nil {
		idents = RouteHopIdentities{}
	}

	p.routeHops = hops
	p.routeHopIdentities = idents
	return hops, idents, nil
}

// AddHop adds a hop to the route and cached hops list.
func (p *ParsedRoute) AddHop(ca *x509.Certificate, hop *Route_Hop, pkey *rsa.PrivateKey) error {
	if p.routeHops == nil {
		_, _, err := p.DecodeHops(ca)
		if err != nil {
			return err
		}
	}

	if err := p.Route.AddHop(hop, pkey); err != nil {
		return err
	}

	p.routeHops = append(p.routeHops, hop)
	return nil
}

func (r *ParsedRoute) SummaryShort(ca *x509.Certificate) (string, error) {
	if len(r.Hop) == 0 {
		return "Route is empty", nil
	}

	_, hopIdentities, err := r.DecodeHops(ca)
	if err != nil {
		return "", err
	}
	return hopIdentities.SummaryShort(ca)
}

// CompareTo checks if two routes are equiv.
func (r *ParsedRoute) CompareTo(ca *x509.Certificate, other *ParsedRoute) bool {
	if len(r.Hop) != len(other.Hop) {
		return false
	}

	if !other.Destination.CompareTo(r.Destination) {
		return false
	}

	_, rHopIds, err := r.DecodeHops(ca)
	if err != nil {
		return false
	}

	_, orHopIds, err := other.DecodeHops(ca)
	if err != nil {
		return false
	}

	for i, hop := range rHopIds {
		otherHop := orHopIds[i]

		if !hop.CompareTo(otherHop) {
			return false
		}
	}

	return true
}

// IsComplete checks if the route goes from source to destination.
func (r *ParsedRoute) IsComplete(ca *x509.Certificate) bool {
	_, hopIds, err := r.DecodeHops(ca)
	if err != nil || len(hopIds) == 0 {
		return false
	}

	lastHop := hopIds[len(hopIds)-1]
	return r.Destination.MatchesIdentity(lastHop)
}

// RouteHops is a set of Route_Hop
type RouteHops []*Route_Hop

// RouteHopIdentities is a set of route hop identities.
type RouteHopIdentities []*identity.ParsedIdentity

// SummaryShort returns the route as a list of hops: ident1 -> ident2 -> ident3
func (hopIdentities RouteHopIdentities) SummaryShort(ca *x509.Certificate) (string, error) {
	if len(hopIdentities) == 0 {
		return "Route is empty", nil
	}

	var result bytes.Buffer
	for i, hopid := range hopIdentities {
		pkh, err := hopid.HashPublicKey()
		if err != nil {
			return "", err
		}
		if i != 0 {
			result.WriteString(" -> ")
		}
		result.WriteString(pkh.MarshalHashIdentifier())
	}

	return result.String(), nil
}

// FindPartialHash checks if the RouteHopIdentities contains another identity.
func (hopIdentities RouteHopIdentities) FindPartialHash(partialHash []byte) *identity.ParsedIdentity {
	for _, ii := range hopIdentities {
		pkh, err := ii.HashPublicKey()
		if err != nil {
			continue
		}

		if pkh.MatchesPartialHash(partialHash) {
			return ii
		}
	}

	return nil
}

// Verify checks everything about the RouteHops.
func (hops RouteHops) Verify(
	ca *x509.Certificate,
	hopSignatures []*signature.SignedMessage,
	hopIdentities RouteHopIdentities,
) error {
	if len(hopIdentities) != len(hops) {
		return errors.New("Number of identities does not match number of hops.")
	}

	if len(hopSignatures) != len(hops) {
		return errors.New("Number of signed hops not match number of hops.")
	}

	// Check for loops in the route.
	var segmentBuf bytes.Buffer
	seenIdentities := make(map[identity.PublicKeyHash]bool)
	for i, hop := range hops {
		hopData := hopSignatures[i].Message
		// Check the segments prior
		if hop.SegmentHash == nil {
			return fmt.Errorf("Hop %d did not have a segment hash.", i)
		}
		if err := hop.SegmentHash.Verify(segmentBuf.Bytes()); err != nil {
			return err
		}

		// Check the hop identity.
		ident := hopIdentities[i]
		hashPtr, err := ident.HashPublicKey()
		if err != nil {
			return err
		}
		hash := *hashPtr
		if _, ok := seenIdentities[hash]; ok {
			summary, err := hopIdentities.SummaryShort(ca)
			var errTxt string
			if err != nil {
				errTxt = err.Error()
			} else {
				errTxt = summary
			}
			return fmt.Errorf("Route cannot contain loops: %s", errTxt)
		}
		seenIdentities[hash] = true

		// Check the next identity
		nextIdent := hop.Next
		if err := nextIdent.Verify(); err != nil {
			return err
		}
		if len(hopIdentities) > i+1 {
			knownNextIdent := hopIdentities[i+1]
			if !nextIdent.MatchesIdentity(knownNextIdent) {
				pkh, err := knownNextIdent.HashPublicKey()
				if err != nil {
					return err
				}

				return fmt.Errorf(
					"Route hop [%d] selects next peer %s != actual %s",
					i,
					nextIdent.MarshalHashIdentifier(),
					pkh.MarshalHashIdentifier(),
				)
			}
		}

		// Write the segment to the buffer
		if _, err := segmentBuf.Write(hopData); err != nil {
			return err
		}
	}

	return nil
}

// NewRoute creates an empty route.
func NewRoute() *Route {
	return &Route{}
}

// HashRouteSegments returns the hash of the route segments.
func (r *Route) HashRouteSegments() (*signature.DataHash, error) {
	var segBuffer bytes.Buffer
	for _, seg := range r.Hop {
		if _, err := segBuffer.Write(seg.Message); err != nil {
			return nil, err
		}
	}

	return signature.NewDataHash(signature.ESignedMessageHash_HASH_SHA256, segBuffer.Bytes())
}

// PopHop removes the last hop.
func (r *Route) PopHop() {
	if len(r.Hop) == 0 {
		return
	}

	r.Hop = r.Hop[:len(r.Hop)-1]
}

// AddHop adds a hop to the route.
func (r *Route) AddHop(hop *Route_Hop, pkey *rsa.PrivateKey) error {
	dh, err := r.HashRouteSegments()
	if err != nil {
		return err
	}

	hop.SegmentHash = dh
	hop.Timestamp = timestamp.Now()

	hm, err := signature.NewSignedMessage(
		signature.ESignedMessageHash_HASH_SHA256,
		hopSignatureSaltLen,
		hop,
		pkey,
	)
	if err != nil {
		return err
	}

	r.Hop = append(r.Hop, hm)
	return nil
}

// DecodeHops decodes and verifies the encoded hops array and signatures.
func (r *Route) DecodeHops(caCert *x509.Certificate) (RouteHops, RouteHopIdentities, error) {
	result := make(RouteHops, len(r.Hop))
	resultIdentities := make(RouteHopIdentities, len(r.Hop))

	for i, bin := range r.Hop {
		h := &Route_Hop{}
		if err := proto.Unmarshal(bin.Message, h); err != nil {
			return nil, nil, err
		}
		if h.Identity == nil {
			return nil, nil, errors.New("Hop must have an identity assigned.")
		}
		pident := identity.NewParsedIdentity(h.Identity)
		if err := pident.VerifyMessage(caCert, bin); err != nil {
			return nil, nil, err
		}
		result[i] = h
		resultIdentities[i] = pident
	}

	return result, nil, nil
}
