package route

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/signature"
	"github.com/golang/protobuf/proto"
)

// ParsedRoute is a fully parsed route.
type ParsedRoute struct {
	*Route

	routeHops          []*Route_Hop
	routeHopIdentities []*identity.ParsedIdentity
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

// SummaryShort returns the route as a list of hops: ident1 -> ident2 -> ident3
func (p *ParsedRoute) SummaryShort(ca *x509.Certificate) (string, error) {
	if len(p.Hop) == 0 {
		return "Route is empty", nil
	}

	_, hopIdentities, err := p.DecodeHops(ca)
	if err != nil {
		return "", err
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

// Verify attempts to parse and verify the entire route.
func (p *ParsedRoute) Verify(ca *x509.Certificate) error {
	_, hopIdentities, err := p.DecodeHops(ca)
	if err != nil {
		return err
	}

	// Check for loops in the route.
	seenIdentities := make(map[identity.PublicKeyHash]bool)
	for _, ident := range hopIdentities {
		hashPtr, err := ident.HashPublicKey()
		if err != nil {
			return err
		}
		hash := *hashPtr
		if _, ok := seenIdentities[hash]; ok {
			summary, err := p.SummaryShort(ca)
			var errTxt string
			if err != nil {
				errTxt = err.Error()
			} else {
				errTxt = summary
			}
			return fmt.Errorf("Route cannot contain loops: %s", errTxt)
		}
		seenIdentities[hash] = true
	}

	return nil
}

// DecodeHops returns the parsed list of hops and caches it for future use.
func (p *ParsedRoute) DecodeHops(ca *x509.Certificate) ([]*Route_Hop, []*identity.ParsedIdentity, error) {
	if p.routeHops != nil {
		return p.routeHops, p.routeHopIdentities, nil
	}

	hops, idents, err := p.Route.DecodeHops(ca)
	if err != nil {
		return nil, nil, err
	}

	if hops == nil {
		hops = []*Route_Hop{}
	}
	if idents == nil {
		idents = []*identity.ParsedIdentity{}
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

// RouteHops is a set of Route_Hop
type RouteHops []*Route_Hop

// NewRoute creates an empty route.
func NewRoute() *Route {
	return &Route{}
}

// AddHop adds a hop to the route.
func (r *Route) AddHop(hop *Route_Hop, pkey *rsa.PrivateKey) error {
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
func (r *Route) DecodeHops(caCert *x509.Certificate) ([]*Route_Hop, []*identity.ParsedIdentity, error) {
	result := make([]*Route_Hop, len(r.Hop))
	resultIdentities := make([]*identity.ParsedIdentity, len(r.Hop))

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
