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

package tpmsrk

import (
	"crypto/x509"
	"errors"
	"fmt"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrAlgorithm is returned when tpm.ssrk names a key algorithm a storage
// root key cannot use (only RSA and ECC have a TCG SRK template). It is
// FailedPrecondition on every transport.
type ErrAlgorithm struct {
	Algorithm string
}

// Error returns the message.
func (e *ErrAlgorithm) Error() string {
	return fmt.Sprintf("tpm.ssrk algorithm %q has no SRK template (RSA or ECC)", e.Algorithm)
}

// GRPCStatus classifies the error as FailedPrecondition.
func (e *ErrAlgorithm) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrNotConfigured is returned when the TPM configuration names no Shared
// SRK handle, so there is nowhere to persist one. It is FailedPrecondition
// on every transport.
type ErrNotConfigured struct{}

// Error returns the message.
func (ErrNotConfigured) Error() string { return "tpm.ssrk configures no Shared SRK handle" }

// GRPCStatus classifies the error as FailedPrecondition.
func (e ErrNotConfigured) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrExists is returned when the Shared SRK handle already holds a
// persistent object. TPM2_EvictControl (TPM 2.0 Library Part 3 §28.5)
// cannot persist a second object at an occupied handle. It is AlreadyExists
// on every transport.
type ErrExists struct {
	Handle uint32
}

// Error returns the message.
func (e ErrExists) Error() string {
	return fmt.Sprintf("shared SRK already exists at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as AlreadyExists.
func (e ErrExists) GRPCStatus() *status.Status {
	return status.New(codes.AlreadyExists, e.Error())
}

// ErrNotFound is returned when Delete finds no persistent object at the
// Shared SRK handle (TPM_RC_HANDLE). It is NotFound on every transport.
type ErrNotFound struct {
	Handle uint32
}

// Error returns the message.
func (e ErrNotFound) Error() string {
	return fmt.Sprintf("shared SRK not found at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as NotFound.
func (e ErrNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrHandleMismatch is returned when Delete is asked to evict a handle
// other than the configured Shared SRK, including a missing (zero) handle.
// Delete evicts only tpm.ssrk, so any other request is refused before the
// TPM is touched rather than silently evicting the SSRK and orphaning its
// sealed children. It is InvalidArgument on every transport.
type ErrHandleMismatch struct {
	Requested  uint32
	Configured uint32
}

// Error returns the message.
func (e ErrHandleMismatch) Error() string {
	return fmt.Sprintf("invalid SRK handle 0x%08X: only the configured shared SRK 0x%08X can be deleted",
		e.Requested, e.Configured)
}

// GRPCStatus maps the error to InvalidArgument.
func (e ErrHandleMismatch) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// AttributesFromConfig builds the creation attributes of the Shared SRK
// from tpm.ssrk: the TCG SRK template for its algorithm, a primary under
// the owner hierarchy, persisted at the configured handle, with no
// platform policy (SRKConfig cannot express one). The algorithm is RSA
// unless the config names ECC. Empty passwords stay nil so the TPM's
// empty default auth is used.
//
// The SDK's TrustedPlatformModule.SSRKAttributes cannot serve here: it reads
// the public area back from the handle, which is TPM_RC_HANDLE until the key
// exists, and its result carries no creation template.
func AttributesFromConfig(cfg *xkmssdk.SRKConfig) (*xkmssdk.KeyAttributes, error) {
	algorithm := x509.RSA
	template := xkmssdk.RSASRKTemplate
	if cfg.KeyAlgorithm != "" {
		parsed, err := xkmssdk.ParseKeyAlgorithm(cfg.KeyAlgorithm)
		if err != nil {
			return nil, err
		}
		algorithm = parsed
	} else if cfg.RSAConfig == nil && cfg.ECCConfig != nil {
		algorithm = x509.ECDSA
	}
	switch algorithm {
	case x509.RSA:
	case x509.ECDSA:
		template = libtpm2.ECCSRKTemplate
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
		cn = "shared-srk"
	}
	return &xkmssdk.KeyAttributes{
		CN:           cn,
		Debug:        cfg.Debug,
		KeyAlgorithm: algorithm,
		KeyType:      xkmssdk.KeyTypeStorage,
		Password:     password,
		StoreType:    xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:        xkmssdk.TPMHandle(cfg.Handle),
			HandleType:    xkmssdk.TPMHTPersistent,
			Hierarchy:     xkmssdk.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
			Template:      template,
		},
	}, nil
}

// Persist creates the Shared SRK cfg describes and persists it at its
// handle. With bus encryption on, the EK salts the session (CreateSRK
// salts only when a parent is given). It does not probe the handle first;
// callers that need to refuse an occupied handle use Create.
func Persist(tpm xkmssdk.TrustedPlatformModule, cfg *xkmssdk.SRKConfig, encryptSession bool) (*xkmssdk.KeyAttributes, error) {
	attrs, err := AttributesFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	if encryptSession {
		ekAttrs, err := tpm.EKAttributes()
		if err != nil {
			return nil, err
		}
		attrs.Parent = ekAttrs
	}
	if err := tpm.CreateSRK(attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}

// Create is the single CreateSRK entry point shared by every daemon
// transport (gRPC, REST, Unix, QUIC, MCP). It creates the Shared SRK the
// TPM configuration names (tpm.ssrk) at its handle and returns its
// attributes. It refuses an occupied handle with ErrExists and a missing
// tpm.ssrk with ErrNotConfigured; a nil TPM is ErrTPMUnavailable.
func Create(tpm xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) {
	if tpm == nil {
		return nil, ErrTPMUnavailable{}
	}
	cfg := tpm.Config()
	if cfg == nil || cfg.SSRK == nil || cfg.SSRK.Handle == 0 {
		return nil, ErrNotConfigured{}
	}
	handle := cfg.SSRK.Handle

	// A readable public area means an object is persisted at the handle.
	// Any read error leaves the decision to TPM2_CreatePrimary, which
	// reports its own failure.
	if _, _, err := tpm.ReadHandle(xkmssdk.TPMHandle(handle)); err == nil {
		return nil, ErrExists{Handle: handle}
	}
	return Persist(tpm, cfg.SSRK, cfg.EncryptSession)
}

// Delete is the single DeleteSRK entry point shared by every daemon
// transport. It evicts the Shared SRK the TPM configuration names
// (tpm.ssrk) from its persistent handle with TPM2_EvictControl (TPM 2.0
// Library Part 3 §28.5), authorised by the owner hierarchy auth it was
// persisted with, so a following Create at the same handle succeeds. It
// returns the evicted handle. The caller names the handle it means to
// evict: anything but the configured tpm.ssrk handle, a missing (zero)
// handle included, is ErrHandleMismatch and evicts nothing. An empty
// handle is ErrNotFound and a missing tpm.ssrk handle ErrNotConfigured; a
// nil TPM is ErrTPMUnavailable.
func Delete(tpm xkmssdk.TrustedPlatformModule, requested uint32) (uint32, error) {
	if tpm == nil {
		return 0, ErrTPMUnavailable{}
	}
	cfg := tpm.Config()
	if cfg == nil || cfg.SSRK == nil || cfg.SSRK.Handle == 0 {
		return 0, ErrNotConfigured{}
	}
	handle := cfg.SSRK.Handle
	if requested != handle {
		return 0, ErrHandleMismatch{Requested: requested, Configured: handle}
	}

	name, _, err := tpm.ReadHandle(xkmssdk.TPMHandle(handle))
	if errors.Is(err, libtpm2.TPMRCHandle) {
		return 0, ErrNotFound{Handle: handle}
	}
	if err != nil {
		return 0, err
	}
	attrs, err := AttributesFromConfig(cfg.SSRK)
	if err != nil {
		return 0, err
	}
	attrs.TPMAttributes.Name = name
	if err := tpm.DeleteKey(attrs, nil); err != nil {
		return 0, err
	}
	return handle, nil
}
