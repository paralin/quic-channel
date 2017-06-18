package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// peerIdentifierRegex identifies "ukfl5oaehyimvpvg" for example
var peerIdentifierRegex = regexp.MustCompile("^[a-z2-7]{16}$")

// ParsePeerIdentifier parses a peer identifier to a PeerIdentifier
func BuildPeerIdentifier(id string) (*PeerIdentifier, error) {
	if !peerIdentifierRegex.MatchString(id) {
		return nil, fmt.Errorf("Not a valid peer identifier: %s", id)
	}

	ident := &PeerIdentifier{}
	dat, err := base32.StdEncoding.DecodeString(strings.ToUpper(id))
	if err != nil {
		return nil, err
	}
	ident.MatchPublicKey = dat
	if len(ident.MatchPublicKey) != 10 {
		return nil, fmt.Errorf("Expected 10 byte identifier, got %d bytes.", len(ident.MatchPublicKey))
	}

	return ident, nil
}

// Verify checks the identifier is valid.
func (d *PeerIdentifier) Verify() error {
	if d == nil {
		return errors.New("Peer identifier is empty.")
	}

	if d.MatchPublicKey == nil {
		return errors.New("Identifier with no known match types given.")
	}

	if len(d.MatchPublicKey) < 10 || len(d.MatchPublicKey) > sha256.Size {
		return errors.New("Public key match was of invalid length.")
	}

	return nil
}

// CompareTo checks if the two identifiers are equal.
func (d *PeerIdentifier) CompareTo(other *PeerIdentifier) bool {
	if d == other {
		return true
	}
	if d == nil {
		return false
	}

	if err := d.Verify(); err != nil {
		return false
	}
	if err := other.Verify(); err != nil {
		return false
	}

	minLen := len(d.MatchPublicKey)
	if len(other.MatchPublicKey) < minLen {
		minLen = len(other.MatchPublicKey)
	}

	return bytes.Compare(d.MatchPublicKey[:minLen], other.MatchPublicKey[:minLen]) == 0
}

// MatchesIdentity checks if the peer identifier selects the identity.
func (d *PeerIdentifier) MatchesIdentity(ident *ParsedIdentity) bool {
	pkh, err := ident.HashPublicKey()
	if err != nil {
		return false
	}

	return pkh.MatchesPartialHash(d.MatchPublicKey)
}

// MarshalHashIdentifier returns the 10-byte string peer identifier representation.
func (d *PeerIdentifier) MarshalHashIdentifier() string {
	var pkh PublicKeyHash
	copy(pkh[:], d.MatchPublicKey)
	return pkh.MarshalHashIdentifier()
}

// HumanString represents the identifier as a human readable string
func (d *PeerIdentifier) HumanString() string {
	if err := d.Verify(); err != nil {
		return fmt.Sprintf("Invalid: %v", err.Error())
	}

	return fmt.Sprintf("Peer: %s", d.MarshalHashIdentifier())
}
