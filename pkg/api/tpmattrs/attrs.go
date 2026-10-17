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

// Package tpmattrs reads the TPM's capability lists and platform
// attributes once for every daemon transport (gRPC, Unix, embedded,
// REST, QUIC, MCP), so each one returns the same fields built the same
// way.
package tpmattrs

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// CapabilityReader is the part of the TPM a capability read needs.
type CapabilityReader interface {
	SupportedAlgorithms() ([]string, error)
	SupportedCommands() ([]string, error)
	SupportedECCCurves() ([]string, error)
}

// PlatformReader is the part of the TPM a platform-attribute read needs.
type PlatformReader interface {
	Device() string
	IsFIPS140_2() (bool, error)
	IsPlatformPCRExtended() (bool, error)
	CanSeal() bool
	Config() *xkmssdk.TPMConfig
	FixedProperties() (*xkmssdk.PropertiesFixed, error)
	EKAttributes() (*xkmssdk.KeyAttributes, error)
	SSRKAttributes() (*xkmssdk.KeyAttributes, error)
	IAKAttributes() (*xkmssdk.KeyAttributes, error)
}

// Capability list names, used in ErrCapabilityRead.
const (
	ListAlgorithms = "algorithms"
	ListCommands   = "commands"
	ListECCCurves  = "ecc_curves"
)

// ErrCapabilityRead is returned when the TPM refuses one of the
// capability lists. It unwraps to the TPM's error.
type ErrCapabilityRead struct {
	List  string
	Cause error
}

// Error returns the message.
func (e ErrCapabilityRead) Error() string {
	return fmt.Sprintf("TPM capability read failed (%s): %v", e.List, e.Cause)
}

// Unwrap returns the TPM's error.
func (e ErrCapabilityRead) Unwrap() error { return e.Cause }

// GRPCStatus classes a refused read as FailedPrecondition on every
// transport, whatever the TPM's own message says.
func (e ErrCapabilityRead) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// Capabilities are the algorithms, commands and ECC curves the TPM
// implements, as TPM2_GetCapability reports them.
type Capabilities struct {
	Algorithms []string
	Commands   []string
	ECCCurves  []string
}

// ReadCapabilities reads the three capability lists. Any list the TPM
// refuses fails the whole read.
func ReadCapabilities(tpm CapabilityReader) (Capabilities, error) {
	algorithms, err := tpm.SupportedAlgorithms()
	if err != nil {
		return Capabilities{}, ErrCapabilityRead{List: ListAlgorithms, Cause: err}
	}
	commands, err := tpm.SupportedCommands()
	if err != nil {
		return Capabilities{}, ErrCapabilityRead{List: ListCommands, Cause: err}
	}
	curves, err := tpm.SupportedECCCurves()
	if err != nil {
		return Capabilities{}, ErrCapabilityRead{List: ListECCCurves, Cause: err}
	}
	return Capabilities{Algorithms: algorithms, Commands: commands, ECCCurves: curves}, nil
}

// KeyRef names a provisioned key by its persistent handle and algorithm.
type KeyRef struct {
	Handle    uint32
	Algorithm string
}

// Platform describes the TPM the daemon runs on and the identity keys
// provisioned in it.
type Platform struct {
	Device       string
	IsFIPS       bool
	PCRExtended  bool
	CanSeal      bool
	IsSimulator  bool
	Manufacturer string
	// EK, SRK and IAK are nil when that key is not provisioned.
	EK  *KeyRef
	SRK *KeyRef
	IAK *KeyRef
}

// ReadPlatform reads the platform attributes. It never fails: an
// attribute the TPM cannot report is left at its zero value, and a key
// that is not provisioned is nil, so the read describes a partly
// provisioned TPM instead of refusing to.
func ReadPlatform(tpm PlatformReader) Platform {
	platform := Platform{
		Device:  tpm.Device(),
		CanSeal: tpm.CanSeal(),
		EK:      keyRef(tpm.EKAttributes()),
		SRK:     keyRef(tpm.SSRKAttributes()),
		IAK:     keyRef(tpm.IAKAttributes()),
	}
	if isFIPS, err := tpm.IsFIPS140_2(); err == nil {
		platform.IsFIPS = isFIPS
	}
	if extended, err := tpm.IsPlatformPCRExtended(); err == nil {
		platform.PCRExtended = extended
	}
	if cfg := tpm.Config(); cfg != nil {
		platform.IsSimulator = cfg.UseSimulator
	}
	if props, err := tpm.FixedProperties(); err == nil && props != nil {
		platform.Manufacturer = props.Manufacturer
	}
	return platform
}

// keyRef returns the key's handle and algorithm, or nil when the key
// is absent.
func keyRef(attrs *xkmssdk.KeyAttributes, err error) *KeyRef {
	if err != nil || attrs == nil || attrs.TPMAttributes == nil {
		return nil
	}
	return &KeyRef{
		Handle:    uint32(attrs.TPMAttributes.Handle),
		Algorithm: attrs.KeyAlgorithm.String(),
	}
}

// Version is the TPM specification family Info reports on the
// transports that carry it as text (QUIC, MCP, the CLI's JSON). The
// daemon drives TPM 2.0 only; gRPC carries it as TPM_VERSION_2_0.
const Version = "2.0"

// PCRReader is the part of the TPM a PCR-bank read needs.
type PCRReader interface {
	ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error)
}

// ActivePCRBanks names the PCR banks the TPM has allocated, as lower-case
// hash names ("sha1", "sha256", ...), in the order the TPM reports them.
// It reads PCR 0 of each bank, which every allocated bank holds. Like
// ReadPlatform it never fails: a TPM that refuses the read reports no
// banks, so Info still describes the rest of the TPM.
func ActivePCRBanks(tpm PCRReader) []string {
	banks, err := tpm.ReadPCRs([]uint{0})
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(banks))
	seen := make(map[string]bool, len(banks))
	for _, bank := range banks {
		name := strings.ToLower(bank.Algorithm)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}
