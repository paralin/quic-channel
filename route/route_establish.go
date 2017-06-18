package route

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/fuserobotics/quic-channel/signature"
	"github.com/golang/protobuf/proto"
)

// ParseVerifyRoute parses and verifies the route.
func (e *RouteEstablish) ParseVerifyRoute(ca *x509.Certificate) (*ParsedRoute, error) {
	ro := &Route{}
	if err := proto.Unmarshal(e.Route, ro); err != nil {
		return nil, err
	}

	pr := BuildParsedRoute(ro)
	if err := pr.Verify(ca); err != nil {
		return nil, err
	}

	if !pr.IsComplete(ca) {
		return nil, errors.New("Cannot RouteEstablish without a complete route.")
	}

	return pr, nil
}

// VerifySignatures checks the signatures. Returns true/false complete and error
func (e *RouteEstablish) VerifySignatures(ca *x509.Certificate, pr *ParsedRoute) (bool, error) {
	_, hopIdentities, err := pr.DecodeHops(ca)
	if err != nil {
		return false, err
	}
	if len(e.RouteSignatures) > len(hopIdentities) {
		return false, errors.New("There cannot be more signatures than hops.")
	}

	for i, sig := range e.RouteSignatures {
		hopIdent := hopIdentities[len(hopIdentities)-1-i]
		sig.Message = e.Route
		defer func() { sig.Message = nil }()
		if err := hopIdent.VerifyMessage(ca, sig); err != nil {
			return false, err
		}
	}

	return len(e.RouteSignatures) == len(hopIdentities), nil
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
