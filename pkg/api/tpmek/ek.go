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

// Package tpmek contains the single CreateEK entry point shared by every
// daemon transport (gRPC, REST, Unix, QUIC, MCP).
//
// The SDK's TrustedPlatformModule.EKAttributes caches the attributes it
// reads back from the persistent EK handle, and those carry no creation
// template. Handing them to CreateEK makes go-tpm marshal a zero
// TPMT_PUBLIC (TPM 2.0 Library Part 2 §12.2.4), which panics with "no
// union member for tag 0". Create refuses that input with a typed error
// instead, so no transport can crash the daemon through it.
package tpmek

import (
	"crypto/x509"
	"errors"
	"fmt"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrTPMUnavailable is returned when no TPM service is wired.
// It is Unavailable on every transport.
type ErrTPMUnavailable struct{}

// Error returns the message.
func (ErrTPMUnavailable) Error() string { return "TPM service not available" }

// GRPCStatus classifies the error as Unavailable.
func (e ErrTPMUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrEKExists is returned when the EK handle already holds a persistent
// object. TPM2_EvictControl (TPM 2.0 Library Part 3 §28.5) cannot persist
// a second object at an occupied handle. It is AlreadyExists on every
// transport.
type ErrEKExists struct {
	Handle uint32
}

// Error returns the message.
func (e ErrEKExists) Error() string {
	return fmt.Sprintf("endorsement key already exists at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as AlreadyExists.
func (e ErrEKExists) GRPCStatus() *status.Status {
	return status.New(codes.AlreadyExists, e.Error())
}

// ErrNotFound is returned when Delete finds no persistent object at the EK
// handle (TPM_RC_HANDLE). It is NotFound on every transport.
type ErrNotFound struct {
	Handle uint32
}

// Error returns the message.
func (e ErrNotFound) Error() string {
	return fmt.Sprintf("endorsement key not found at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as NotFound.
func (e ErrNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrNotConfigured is returned when the TPM configuration names no EK
// handle, so there is nowhere to persist one. It is FailedPrecondition on
// every transport.
type ErrNotConfigured struct{}

// Error returns the message.
func (ErrNotConfigured) Error() string { return "tpm.ek configures no endorsement key handle" }

// GRPCStatus classifies the error as FailedPrecondition.
func (e ErrNotConfigured) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrAlgorithm is returned when tpm.ek names a key algorithm an EK cannot
// use (the TCG EK Credential Profile defines only RSA and ECC templates).
// It is FailedPrecondition on every transport.
type ErrAlgorithm struct {
	Algorithm string
}

// Error returns the message.
func (e *ErrAlgorithm) Error() string {
	return fmt.Sprintf("tpm.ek algorithm %q has no EK template (RSA or ECC)", e.Algorithm)
}

// GRPCStatus classifies the error as FailedPrecondition.
func (e *ErrAlgorithm) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// AttributesFromConfig builds the creation attributes of the EK from tpm.ek:
// the TCG EK Credential Profile template for its algorithm (RSA unless the
// config names ECC), a primary under the endorsement hierarchy, persisted at
// the configured handle. CreateEK applies the platform policy digest itself
// when PlatformPolicy is set, and stamps the key type. Empty passwords stay
// nil so the TPM's empty default auth is used.
//
// The SDK's TrustedPlatformModule.EKAttributes cannot serve here: it reads
// the public area back from the handle, which is TPM_RC_HANDLE once
// TPM2_Clear has emptied it, and its result carries no creation template.
func AttributesFromConfig(cfg *xkmssdk.EKConfig) (*xkmssdk.KeyAttributes, error) {
	algorithm := x509.RSA
	if cfg.KeyAlgorithm != "" {
		parsed, err := xkmssdk.ParseKeyAlgorithm(cfg.KeyAlgorithm)
		if err != nil {
			return nil, err
		}
		algorithm = parsed
	} else if cfg.RSAConfig == nil && cfg.ECCConfig != nil {
		algorithm = x509.ECDSA
	}
	var template libtpm2.TPMTPublic
	switch algorithm {
	case x509.RSA:
		template = libtpm2.RSAEKTemplate
	case x509.ECDSA:
		template = libtpm2.ECCEKTemplate
	default:
		return nil, &ErrAlgorithm{Algorithm: cfg.KeyAlgorithm}
	}

	var password, hierarchyAuth xkmssdk.Password
	var err error
	if cfg.Password != "" {
		if password, err = xkmssdk.NewPassword([]byte(cfg.Password)); err != nil {
			return nil, err
		}
	}
	if cfg.HierarchyAuth != "" {
		if hierarchyAuth, err = xkmssdk.NewPassword([]byte(cfg.HierarchyAuth)); err != nil {
			return nil, err
		}
	}

	cn := cfg.CN
	if cn == "" {
		cn = "ek"
	}
	attrs := &xkmssdk.KeyAttributes{
		CN:             cn,
		Debug:          cfg.Debug,
		KeyAlgorithm:   algorithm,
		Password:       password,
		PlatformPolicy: cfg.PlatformPolicy,
		StoreType:      xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			CertHandle:    xkmssdk.TPMHandle(cfg.CertHandle),
			Handle:        xkmssdk.TPMHandle(cfg.Handle),
			HandleType:    xkmssdk.TPMHTPersistent,
			Hierarchy:     libtpm2.TPMHandle(libtpm2.TPMRHEndorsement),
			HierarchyAuth: hierarchyAuth,
			Template:      template,
		},
	}
	if cfg.RSAConfig != nil {
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: cfg.RSAConfig.KeySize}
	}
	if cfg.ECCConfig != nil {
		curve, err := xkmssdk.ParseCurve(cfg.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: curve}
	}
	return attrs, nil
}

// Create is the single CreateEK entry point shared by every daemon
// transport. It creates the EK the TPM configuration names (tpm.ek) at its
// handle and returns its attributes. It refuses an occupied handle with
// ErrEKExists and a missing tpm.ek handle with ErrNotConfigured; a nil TPM
// is ErrTPMUnavailable.
func Create(tpm xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) {
	if tpm == nil {
		return nil, ErrTPMUnavailable{}
	}
	cfg := tpm.Config()
	if cfg == nil || cfg.EK == nil || cfg.EK.Handle == 0 {
		return nil, ErrNotConfigured{}
	}
	handle := cfg.EK.Handle

	// A readable public area means an object is persisted at the handle.
	// Any read error leaves the decision to TPM2_CreatePrimary, which
	// reports its own failure.
	if _, _, err := tpm.ReadHandle(xkmssdk.TPMHandle(handle)); err == nil {
		return nil, ErrEKExists{Handle: handle}
	}
	ekAttrs, err := AttributesFromConfig(cfg.EK)
	if err != nil {
		return nil, err
	}
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return nil, err
	}
	return ekAttrs, nil
}

// Delete is the single DeleteEK entry point shared by every daemon
// transport. It evicts the EK the TPM configuration names (tpm.ek) from its
// persistent handle with TPM2_EvictControl (TPM 2.0 Library Part 3 §28.5),
// authorised by the hierarchy auth it was persisted with, so a following
// Create at the same handle succeeds. It returns the evicted handle. An
// empty handle is ErrNotFound and a missing tpm.ek handle ErrNotConfigured;
// a nil TPM is ErrTPMUnavailable.
func Delete(tpm xkmssdk.TrustedPlatformModule) (uint32, error) {
	if tpm == nil {
		return 0, ErrTPMUnavailable{}
	}
	cfg := tpm.Config()
	if cfg == nil || cfg.EK == nil || cfg.EK.Handle == 0 {
		return 0, ErrNotConfigured{}
	}
	handle := cfg.EK.Handle

	name, _, err := tpm.ReadHandle(xkmssdk.TPMHandle(handle))
	if errors.Is(err, libtpm2.TPMRCHandle) {
		return 0, ErrNotFound{Handle: handle}
	}
	if err != nil {
		return 0, err
	}
	ekAttrs, err := AttributesFromConfig(cfg.EK)
	if err != nil {
		return 0, err
	}
	ekAttrs.TPMAttributes.Name = name
	if err := tpm.DeleteKey(ekAttrs, nil); err != nil {
		return 0, err
	}
	return handle, nil
}
