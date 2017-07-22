package route

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/fuserobotics/quic-channel/identity"
	"github.com/fuserobotics/quic-channel/signature"
	"github.com/golang/protobuf/proto"
)

// ParseRoute parses the route.
func (e *RouteEstablish) ParseRoute(ca *x509.Certificate) (*ParsedRoute, error) {
	ro := &Route{}
	if err := proto.Unmarshal(e.Route, ro); err != nil {
		return nil, err
	}

	pr := BuildParsedRoute(ro)
	if !pr.IsComplete(ca) {
		return nil, errors.New("cannot RouteEstablish without a complete route")
	}

	return pr, nil
}

// VerifySignatures checks the signatures. Returns true/false complete and error
func (e *RouteEstablish) VerifySignatures(
	ca *x509.Certificate,
	pr *ParsedRoute,
	identityLookup func(peerId *identity.PeerIdentifier) (*identity.ParsedIdentity, error),
) (bool, error) {
	hops, err := pr.DecodeHops(ca)
	if err != nil {
		return false, err
	}
	if len(e.RouteSignatures) > len(hops) {
		return false, errors.New("There cannot be more signatures than hops.")
	}

	for i, hop := range hops[len(hops)-len(e.RouteSignatures):] {
		sig := e.RouteSignatures[len(e.RouteSignatures)-1-i]
		ident, err := identityLookup(hop.Identity)
		if err != nil {
			return false, err
		}
		if ident == nil {
			continue
		}
		sig.Message = e.Route
		defer func() { sig.Message = nil }()
		if err := ident.VerifyMessage(ca, sig); err != nil {
			return false, err
		}
	}

	return len(e.RouteSignatures) == len(hops), nil
}

// SignRoute signs the route and adds the signature to the RouteEstablish.
func (e *RouteEstablish) SignRoute(pkey *rsa.PrivateKey) error {
	msg := &signature.SignedMessage{}
	msg.Message = e.Route
	msg.HashType = signature.ESignedMessageHash_HASH_SHA256
	if err := msg.Sign(pkey); err != nil {
		return err
	}
	msg.Message = nil

	e.RouteSignatures = append(e.RouteSignatures, msg)
	return nil
}
