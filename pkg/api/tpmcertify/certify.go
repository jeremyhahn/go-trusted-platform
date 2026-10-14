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

// Package tpmcertify is the TPM2_Certify operation shared by every daemon
// transport (gRPC, Unix, REST, QUIC, MCP), so each one rejects the same
// requests with the same typed errors and returns the same attestation.
package tpmcertify

import (
	"crypto/x509"
	"errors"
	"fmt"

	tpmgo "github.com/google/go-tpm/tpm2"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// MaxNonceSize is the largest qualifying data accepted: a TPM2B_DATA holds
// at most sizeof(TPMT_HA), the largest digest (SHA-512) plus its algorithm.
const MaxNonceSize = 64

const (
	persistentFirst uint32 = 0x81000000
	persistentLast  uint32 = 0x81FFFFFF
)

// Certifier is the slice of the SDK TrustedPlatformModule Certify needs.
type Certifier interface {
	CertifyKey(keyAttrs *quicbaassdk.KeyAttributes, nonce []byte, backend quicbaassdk.TPMKeyBackend) (*quicbaassdk.CertifyResult, error)
	Config() *quicbaassdk.TPMConfig
}

// Result is a TPM2_Certify attestation in wire form: public keys are PKIX
// DER and the signature algorithm is its x509 name.
type Result struct {
	CertifyInfo            []byte
	Signature              []byte
	SignatureAlgorithm     string
	CertifyInfoSignature   []byte
	AttestingKeyPublic     []byte
	AttestedKeyPublic      []byte
	AttestingKeyPublicArea []byte
	AttestedKeyPublicArea  []byte
	Nonce                  []byte
}

// Certify has the IAK certify that the key at a persistent handle is
// resident in this TPM, over the caller's nonce. password is the certified
// key's authValue, empty when it has none. The configured IDevID is
// certified under its admin policy, as TPM2_Certify requires for it.
func Certify(tpm Certifier, handle uint32, password string, nonce []byte) (*Result, error) {
	if tpm == nil {
		return nil, ErrTPMUnavailable{}
	}
	if handle == 0 {
		return nil, ErrHandleRequired{}
	}
	if handle < persistentFirst || handle > persistentLast {
		return nil, ErrHandleNotPersistent{Handle: handle}
	}
	if len(nonce) > MaxNonceSize {
		return nil, ErrNonceTooLarge{Size: len(nonce)}
	}

	keyAttrs, err := keyAttributes(tpm.Config(), handle, password)
	if err != nil {
		return nil, err
	}
	certified, err := tpm.CertifyKey(keyAttrs, nonce, nil)
	if err != nil {
		if errors.Is(err, tpmgo.TPMRCHandle) {
			return nil, ErrKeyNotFound{Handle: handle}
		}
		return nil, ErrCertifyFailed{Cause: err}
	}
	return toResult(certified)
}

// keyAttributes names the key to certify. Only the handle, the authValue
// and, for the configured IDevID, the key type that selects its admin
// policy are needed for a persistent key.
func keyAttributes(cfg *quicbaassdk.TPMConfig, handle uint32, password string) (*quicbaassdk.KeyAttributes, error) {
	attrs := &quicbaassdk.KeyAttributes{
		CN:            fmt.Sprintf("0x%08X", handle),
		TPMAttributes: &quicbaassdk.TPMAttributes{Handle: tpmgo.TPMHandle(handle)},
	}
	if cfg != nil && cfg.IDevID != nil && cfg.IDevID.Handle == handle {
		attrs.KeyType = quicbaassdk.KeyTypeIDevID
	}
	if password != "" {
		secret, err := quicbaassdk.NewPassword([]byte(password))
		if err != nil {
			return nil, ErrCertifyFailed{Cause: err}
		}
		attrs.Password = secret
	}
	return attrs, nil
}

func toResult(certified *quicbaassdk.CertifyResult) (*Result, error) {
	attesting, err := x509.MarshalPKIXPublicKey(certified.AttestingKeyPublic)
	if err != nil {
		return nil, ErrCertifyFailed{Cause: err}
	}
	attested, err := x509.MarshalPKIXPublicKey(certified.AttestedKeyPublic)
	if err != nil {
		return nil, ErrCertifyFailed{Cause: err}
	}
	return &Result{
		CertifyInfo:            certified.CertifyInfo,
		Signature:              certified.Signature,
		SignatureAlgorithm:     certified.SignatureAlgorithm.String(),
		CertifyInfoSignature:   certified.CertifyInfoSignature,
		AttestingKeyPublic:     attesting,
		AttestedKeyPublic:      attested,
		AttestingKeyPublicArea: certified.AttestingKeyPublicArea,
		AttestedKeyPublicArea:  certified.AttestedKeyPublicArea,
		Nonce:                  certified.Nonce,
	}, nil
}
