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

// tpm_diskless.go is platformd's TPM decision on a diskless node (#690). Such
// a node keeps no local state: its root is a verified read-only image under a
// tmpfs overlay, so every file the disk path consults — the ESP seal
// artifacts, the PPI-clear sentinel, the identity certificates — is gone at
// each boot. What survives is the TPM. Its persistent handles (EK, SSRK,
// Platform SRK, IAK, IDevID; the #681 model in docs/tpm/) are the node's
// identity, so they are what decides whether the node is provisioned.

package app

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	libtpm2 "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

// disklessCmdlinePath is the kernel command line the boot model is read
// from: the one the signed UKI carried. Variable for tests.
var disklessCmdlinePath = "/proc/cmdline"

// ErrBootModelUnreadable is returned when platformd cannot establish the
// boot model. It refuses to guess: the disk path would clear a diskless
// node's TPM on an absent ESP, and the diskless path would skip a disk
// node's seal gate.
type ErrBootModelUnreadable struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *ErrBootModelUnreadable) Error() string {
	return "boot model: cannot read " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrBootModelUnreadable) Unwrap() error { return e.Err }

// bootsDiskless reports whether this boot is a diskless one.
func bootsDiskless() (bool, error) {
	cmdline, err := os.ReadFile(disklessCmdlinePath)
	if err != nil {
		return false, &ErrBootModelUnreadable{Path: disklessCmdlinePath, Err: err}
	}
	model, err := disklessroot.BootModelFromCmdline(string(cmdline))
	if err != nil {
		return false, &ErrBootModelUnreadable{Path: disklessCmdlinePath, Err: err}
	}
	return model == disklessroot.BootModel, nil
}

// ErrTPMHandleUnset is returned when the TPM configuration does not name one
// of the identity handles, so residency cannot be decided.
type ErrTPMHandleUnset struct {
	// Key is the tpm configuration section missing its handle.
	Key string
}

// Error implements the error interface.
func (e *ErrTPMHandleUnset) Error() string {
	return "tpm: the " + e.Key + " persistent handle is not configured"
}

// ErrTPMHandleUnreadable is returned when reading an identity handle fails
// for any reason other than the handle being empty. A diskless node must not
// read a failing TPM as an empty one: provisioning starts with TPM2_Clear.
type ErrTPMHandleUnreadable struct {
	Handle uint32
	Err    error
}

// Error implements the error interface.
func (e *ErrTPMHandleUnreadable) Error() string {
	return fmt.Sprintf("tpm: reading persistent handle 0x%08X: %v", e.Handle, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrTPMHandleUnreadable) Unwrap() error { return e.Err }

// ErrDisklessIdentityUnavailable is returned on a diskless node whose TPM
// holds its identity keys but which could not recover its identity
// certificates from the control plane this boot. The node does not re-mint
// them: re-enrollment recreates the IDevID under the endorsement hierarchy
// auth, which a stateless node does not hold across boots, and every refused
// attempt counts toward the TPM's dictionary-attack lockout. It fails closed
// instead, and the cause says which step refused.
type ErrDisklessIdentityUnavailable struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e ErrDisklessIdentityUnavailable) Error() string {
	msg := "tpm: diskless node holds its identity keys in the TPM but could not recover its " +
		"identity certificates from the control plane (see docs/tpm/architecture.md §4d): " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrDisklessIdentityUnavailable) Unwrap() error { return e.Cause }

// tpmHandleReader reads a persistent object's Name and public area.
type tpmHandleReader interface {
	ReadHandle(handle libtpm2.TPMHandle) (libtpm2.TPM2BName, libtpm2.TPMTPublic, error)
}

// residentKey is one identity handle and the role its object must have.
type residentKey struct {
	key        string
	handle     uint32
	restricted bool
	decrypt    bool
	sign       bool
}

// residentKeys lists the identity handles of cfg with their roles: the EK and
// both storage roots are restricted decryption keys (TPM parents), the IAK is
// a restricted signing key (it signs only TPM-generated attestations), and the
// IDevID is an unrestricted signing key.
func residentKeys(cfg *xkmssdk.TPMConfig) ([]residentKey, error) {
	if cfg.EK == nil || cfg.EK.Handle == 0 {
		return nil, &ErrTPMHandleUnset{Key: "ek"}
	}
	if cfg.SSRK == nil || cfg.SSRK.Handle == 0 {
		return nil, &ErrTPMHandleUnset{Key: "ssrk"}
	}
	if cfg.PlatformSRK == nil || cfg.PlatformSRK.SRKHandle == 0 {
		return nil, &ErrTPMHandleUnset{Key: "platform-srk"}
	}
	if cfg.IAK == nil || cfg.IAK.Handle == 0 {
		return nil, &ErrTPMHandleUnset{Key: "iak"}
	}
	if cfg.IDevID == nil || cfg.IDevID.Handle == 0 {
		return nil, &ErrTPMHandleUnset{Key: "idevid"}
	}
	return []residentKey{
		{key: "ek", handle: cfg.EK.Handle, restricted: true, decrypt: true},
		{key: "ssrk", handle: cfg.SSRK.Handle, restricted: true, decrypt: true},
		{key: "platform-srk", handle: cfg.PlatformSRK.SRKHandle, restricted: true, decrypt: true},
		{key: "iak", handle: cfg.IAK.Handle, restricted: true, sign: true},
		{key: "idevid", handle: cfg.IDevID.Handle, sign: true},
	}, nil
}

// residentPublicKey reads the public half of the key persisted at handle.
func residentPublicKey(tpm tpmHandleReader, handle uint32) (crypto.PublicKey, error) {
	_, public, err := tpm.ReadHandle(libtpm2.TPMHandle(handle))
	if err != nil {
		return nil, err
	}
	return libtpm2.Pub(public)
}

// ErrTPMIdentityPartial is returned on a diskless node whose TPM holds some
// of the identity handles but not all of them, or holds an object that is
// not the identity key its handle names. Neither is an unprovisioned TPM:
// first provisioning starts with TPM2_Clear, which would destroy whatever
// the TPM holds, an enrolled identity included. The node fails closed and
// names the handles; recovering the TPM is an operator decision.
type ErrTPMIdentityPartial struct {
	// Empty names the handles that hold no object.
	Empty []string
	// Mismatched names the handles holding an object of the wrong role, or
	// one whose Name is not that of the public area the TPM returned.
	Mismatched []string
}

// Error implements the error interface.
func (e *ErrTPMIdentityPartial) Error() string {
	msg := "tpm: diskless node's TPM holds a partial or foreign identity; refusing to clear it"
	if len(e.Empty) > 0 {
		msg += "; empty: " + strings.Join(e.Empty, ", ")
	}
	if len(e.Mismatched) > 0 {
		msg += "; mismatched: " + strings.Join(e.Mismatched, ", ")
	}
	return msg + " (see docs/tpm/architecture.md §4d)"
}

// residentTPMIdentity reports whether the TPM holds the node's full identity:
// every configured handle holds a non-duplicable object of its role, under
// the Name of the public area the TPM returned. It reports false only when
// every handle is empty, a genuinely unprovisioned TPM. Anything between the
// two is an *ErrTPMIdentityPartial, and any other read failure is an error.
func residentTPMIdentity(tpm tpmHandleReader, cfg *xkmssdk.TPMConfig) (bool, error) {
	keys, err := residentKeys(cfg)
	if err != nil {
		return false, err
	}
	partial := &ErrTPMIdentityPartial{}
	for _, k := range keys {
		label := fmt.Sprintf("%s (0x%08X)", k.key, k.handle)
		name, pub, err := tpm.ReadHandle(libtpm2.TPMHandle(k.handle))
		if err != nil {
			if errors.Is(err, libtpm2.TPMRCHandle) || errors.Is(err, libtpm2.TPMRCValue) {
				partial.Empty = append(partial.Empty, label)
				continue
			}
			return false, &ErrTPMHandleUnreadable{Handle: k.handle, Err: err}
		}
		if !k.matches(pub) {
			partial.Mismatched = append(partial.Mismatched, label)
			continue
		}
		expected, err := libtpm2.ObjectName(&pub)
		if err != nil {
			return false, &ErrTPMHandleUnreadable{Handle: k.handle, Err: err}
		}
		if string(expected.Buffer) != string(name.Buffer) {
			partial.Mismatched = append(partial.Mismatched, label)
		}
	}
	switch {
	case len(partial.Empty) == 0 && len(partial.Mismatched) == 0:
		return true, nil
	case len(partial.Empty) == len(keys):
		return false, nil
	default:
		return false, partial
	}
}

// matches reports whether pub is a non-duplicable key of this role.
func (k residentKey) matches(pub libtpm2.TPMTPublic) bool {
	attrs := pub.ObjectAttributes
	return attrs.FixedTPM && attrs.FixedParent &&
		attrs.Restricted == k.restricted &&
		attrs.Decrypt == k.decrypt &&
		attrs.SignEncrypt == k.sign
}

// provisionDisklessTPM is InitTPM's provisioning decision on a diskless node.
// A TPM holding the full identity is adopted untouched. A TPM holding none
// of it runs first provisioning, which leaves that identity behind, so it
// runs once. A TPM holding part of it is refused (residentTPMIdentity): the
// clear that starts provisioning is never a repair. Unlike the disk path
// there is no seal probe (a diskless node has no LUKS seal to preserve) and
// no UEFI PPI escalation (its loop guard is a file, and a file does not
// outlive the reset it is meant to bound). It reports whether provisioning
// ran.
func (app *App) provisionDisklessTPM(
	ctx context.Context,
	soPIN, userPIN xkmssdk.Password,
	initParams *AppInitParams) (bool, error) {

	resident, err := residentTPMIdentity(app.TPM, &app.TPMConfig)
	if err != nil {
		return false, err
	}
	if resident {
		app.Logger.Info("Diskless node: TPM-resident identity found, skipping provisioning")
		return false, app.applyDisklessNodeIdentity()
	}

	app.Logger.Info("Diskless node: TPM identity not resident, running first provisioning")
	// Empty lockout auth: the auth of a fresh or PPI-cleared TPM. The disk
	// path's comment on FactoryResetWithClear explains why soPIN is wrong.
	if err := app.TPM.FactoryResetWithClear(nil); err != nil {
		app.Logger.Warn("Diskless node: factory reset refused, provisioning the TPM as found",
			slog.String("error", err.Error()))
	}
	if err := app.provisionTPMHierarchies(soPIN); err != nil {
		return false, err
	}
	// The EK is resident now and nothing is enrolled yet: the identity the
	// enrollment carries is this TPM's, not the image's.
	if err := app.applyDisklessNodeIdentity(); err != nil {
		return false, err
	}
	if _, err := app.provisionPlatformIdentity(ctx, soPIN, userPIN, initParams); err != nil {
		return false, err
	}
	return true, nil
}

// applyDisklessNodeIdentity names a diskless node after its TPM's EK
// (entities.EKNodeIdentity) and makes that name the one its identity is
// enrolled and recovered under. Every node built from one media set boots
// the same platform config and /etc/hostname, so the image's TCG product
// serial, IAK/IDevID Common Names and hostname would give every node the
// same identity; each is overridden here, and the hostname is left
// cosmetic. The EK is read from its persistent handle rather than from
// TPM.EK(), whose cache a freshly opened TPM has not filled.
func (app *App) applyDisklessNodeIdentity() error {
	if app.TPMConfig.EK == nil || app.TPMConfig.IAK == nil || app.TPMConfig.IDevID == nil {
		return ErrDisklessIdentityUnavailable{Reason: "the TPM configuration has no EK, IAK or IDevID section"}
	}
	ekPub, err := residentPublicKey(app.TPM, app.TPMConfig.EK.Handle)
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "the EK cannot be read", Cause: err}
	}
	identity, err := entities.EKNodeIdentity(ekPub)
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "no identity derives from the EK", Cause: err}
	}
	app.nodeIdentity = identity
	app.TPMConfig.IDevID.Serial = identity
	app.TPMConfig.IDevID.CN = identity + "-idevid"
	app.TPMConfig.IAK.CN = identity + "-iak"
	app.Logger.Info("Diskless node: identity derived from the TPM's EK",
		slog.String("identity", identity),
		slog.String("hostname", app.Hostname))
	return nil
}

// enrollmentName is the Common Name this node enrolls its certificates
// under: the EK-derived identity on a diskless node, the hostname on a disk
// node.
func (app *App) enrollmentName() string {
	if app.nodeIdentity != "" {
		return app.nodeIdentity
	}
	return app.Hostname
}
