// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package entities

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// EKNodeIdentityPrefix starts every EK-derived node identity, so a name
// claimed under it can be told from an operator-chosen serial or hostname.
const EKNodeIdentityPrefix = "ek-"

// ekNodeIdentityBytes is how much of the SHA-256 digest the identity keeps:
// 128 bits, and a 35-character name that is still a DNS label.
const ekNodeIdentityBytes = 16

// ErrEKPublicKeyInvalid indicates an endorsement public key that cannot be
// encoded as a SubjectPublicKeyInfo, so no node identity derives from it.
type ErrEKPublicKeyInvalid struct {
	Cause error
}

// Error implements the error interface.
func (e ErrEKPublicKeyInvalid) Error() string {
	return fmt.Sprintf("device: endorsement public key cannot be encoded: %v", e.Cause)
}

// Unwrap returns the underlying encoding error.
func (e ErrEKPublicKeyInvalid) Unwrap() error {
	return e.Cause
}

// EKNodeIdentity derives a node's identity from its TPM's endorsement key:
// "ek-" and the first 128 bits of the SHA-256 of the key's DER
// SubjectPublicKeyInfo, in lower-case hex. Nodes that boot one image share
// every byte of configuration but never an EK, so this is the name a
// diskless node enrolls and recovers its certificates under (#690). The
// node reads the key from its TPM; the control plane reads it from the EK
// certificate the enrollment's credential activation proved, and both
// arrive at the same name through this one function.
func EKNodeIdentity(ekPub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return "", ErrEKPublicKeyInvalid{Cause: err}
	}
	sum := sha256.Sum256(der)
	return EKNodeIdentityPrefix + hex.EncodeToString(sum[:ekNodeIdentityBytes]), nil
}

// IsEKNodeIdentity reports whether name claims to be an EK-derived node
// identity. A claim is only as good as the EK it is checked against.
func IsEKNodeIdentity(name string) bool {
	return strings.HasPrefix(name, EKNodeIdentityPrefix)
}
