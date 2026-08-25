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

// tpm_seal_guard.go carries the seal-preservation gate for platformd's TPM
// recovery path (#61): a TPM2_Clear regenerates the storage primary seed,
// which permanently invalidates every sealed object under the storage
// hierarchy — including the TPM-sealed LUKS unlock firstboot writes to the
// ESP. platformd must never destroy the material the next boot's unlock
// depends on.

package app

import (
	"crypto/x509"
	"errors"
	"os"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// tpmSealArtifactPaths lists the ESP artifacts that prove a TPM-sealed LUKS
// unlock exists. Declared as a variable so tests can point it at fixtures.
var tpmSealArtifactPaths = []string{
	"/boot/efi/tpm2/seal-platform.pub",
	"/boot/efi/tpm2/seal-platform.priv",
}

// tpmSealMountsFile is the mount table consulted to decide whether the ESP
// is actually available when no artifact is found. Variable for tests.
var tpmSealMountsFile = "/proc/mounts"

// tpmSealESPMountPoint is the mount point the artifact paths live under.
var tpmSealESPMountPoint = "/boot/efi"

// tpmSealProbe is the tri-state answer of the ESP seal-artifact probe.
// Present and absent are POSITIVE determinations; indeterminate means the
// probe could not prove either, and the caller must not act as if it had —
// neither by clearing the TPM (a real seal would be stranded) nor by
// silently substituting the partial seal-preserving repair for full
// provisioning (a fresh node would come up without hierarchy auth, CA
// state, or identity enrollment while reporting success).
type tpmSealProbe int

const (
	// tpmSealAbsent: the ESP is demonstrably mounted and the artifacts
	// demonstrably do not exist.
	tpmSealAbsent tpmSealProbe = iota

	// tpmSealPresent: at least one seal artifact exists — even a torn
	// half means a seal-consuming boot chain is in play.
	tpmSealPresent

	// tpmSealIndeterminate: an artifact stat failed with something other
	// than not-exist, or nothing is mounted where the artifacts would
	// live, so their absence proves nothing.
	tpmSealIndeterminate
)

// probeTPMSealArtifacts reports whether the ESP carries a TPM-sealed LUKS
// unlock. ANY present artifact counts. Absence is answered only when the
// ESP is demonstrably available (mounted) and the artifacts demonstrably do
// not exist; everything else is indeterminate, never a guess in either
// direction (#61, round-4 review).
func probeTPMSealArtifacts() tpmSealProbe {
	indeterminate := false
	for _, path := range tpmSealArtifactPaths {
		_, err := os.Stat(path)
		if err == nil {
			return tpmSealPresent
		}
		if !os.IsNotExist(err) {
			indeterminate = true
		}
	}
	if indeterminate || !tpmSealESPVerified() {
		return tpmSealIndeterminate
	}
	return tpmSealAbsent
}

// tpmSealESPMounted reports whether the ESP mount point appears in the
// mount table. An unreadable mount table also fails safe (true would let
// the not-exist answer stand, so report "not verified" → indeterminate).
//
// A mount-point string match alone is NOT proof the real ESP is mounted
// (round-5 review): an empty tmpfs, a bind mount, or the wrong partition
// at /boot/efi would make the artifacts' absence look like proof while the
// real seal sits on the unmounted ESP. The filesystem must therefore also
// LOOK like the node's ESP: mounted from a /dev block device, vfat (the
// only filesystem an EFI System Partition can be), and carrying the EFI/
// directory every ESP this platform booted from necessarily has (the UKI
// and boot entries live under it). Anything else is unverified and the
// probe answers indeterminate rather than authorizing a destructive clear.
func tpmSealESPVerified() bool {
	data, err := os.ReadFile(tpmSealMountsFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != tpmSealESPMountPoint {
			continue
		}
		if !strings.HasPrefix(fields[0], "/dev/") || fields[2] != "vfat" {
			return false
		}
		info, statErr := os.Stat(tpmSealESPMountPoint + "/EFI")
		return statErr == nil && info.IsDir()
	}
	return false
}

// ErrTPMSealStateUnknown is returned when TPM recovery is required but the
// seal-artifact probe could not determine whether a TPM-sealed LUKS unlock
// exists on the ESP. Recovery refuses to guess: clearing would strand a
// real seal, and substituting the partial repair for full provisioning
// would bring a fresh node up unprovisioned while reporting success.
type ErrTPMSealStateUnknown struct {
	// Detail names what made the probe indeterminate.
	Detail string
}

// Error implements the error interface.
func (e ErrTPMSealStateUnknown) Error() string {
	msg := "tpm: recovery required but the ESP seal state is indeterminate — " +
		"mount " + tpmSealESPMountPoint + " (or repair its filesystem) so the seal probe " +
		"can prove whether a TPM-sealed LUKS unlock exists, then restart platformd"
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// tpmRecoveryAction is the recovery InitTPM runs when TPM provisioning is
// required.
type tpmRecoveryAction int

const (
	// tpmRecoverFullProvision: destructive recovery (factory reset, then
	// ProvisionPlatform) — only ever chosen on a PROVEN seal-free node.
	tpmRecoverFullProvision tpmRecoveryAction = iota

	// tpmRecoverSealPreserving: the non-clearing, non-evicting repair —
	// chosen when seal artifacts are proven present.
	tpmRecoverSealPreserving
)

// tpmProvisionCause records WHY InitTPM decided provisioning is required.
// The recovery decision needs the cause, not just a boolean: the
// seal-preserving repair can install missing objects, but it deliberately
// cannot evict or recreate an EXISTING Platform SRK, so a cause the repair
// cannot fix must not be routed through it (round-7 review).
type tpmProvisionCause int

const (
	// tpmCauseUnprovisioned: EK/IAK/Platform SRK missing (fresh or
	// partially provisioned TPM) — the install-only repair can create
	// what is missing.
	tpmCauseUnprovisioned tpmProvisionCause = iota

	// tpmCausePolicyDrift: the existing Platform SRK's AuthPolicy no
	// longer matches the current PlatformPolicyDigest. Only recreating
	// the SRK can fix this, which the seal-preserving repair must never
	// do — the seal is parented under that SRK.
	tpmCausePolicyDrift
)

// ErrTPMSealPolicyDrift is returned when seal artifacts exist but the
// Platform SRK they are parented under carries a drifted authorization
// policy. The repair cannot fix this without destroying the seal parent,
// and continuing would adopt an SRK whose policy-authorized operations all
// fail while startup reports success.
type ErrTPMSealPolicyDrift struct{}

// Error implements the error interface.
func (ErrTPMSealPolicyDrift) Error() string {
	return "tpm: a TPM-sealed LUKS unlock exists but the Platform SRK's authorization policy " +
		"no longer matches the current platform PCR state (firmware, Secure Boot, or boot-chain " +
		"change) — the seal cannot be preserved across an SRK policy migration. Recover by " +
		"restoring the prior PCR state, or unlock with the recovery key and remove the ESP seal " +
		"artifacts (" + tpmSealArtifactPathsSummary() + ") to authorize re-provisioning, then restart platformd"
}

// tpmSealArtifactPathsSummary renders the artifact paths for operator-facing
// error text.
func tpmSealArtifactPathsSummary() string {
	return strings.Join(tpmSealArtifactPaths, ", ")
}

// resolveTPMRecovery maps the tri-state seal probe and the provisioning
// cause onto the recovery action. Two situations are typed errors, never
// guesses: an indeterminate probe (clearing would strand a real seal;
// substituting the partial repair for full provisioning would bring a
// fresh node up unprovisioned while reporting success — round-4 review),
// and a present seal whose parent SRK has policy drift (the repair cannot
// recreate the seal parent, so "success" would leave every
// policy-authorized operation failing — round-7 review).
func resolveTPMRecovery(probe tpmSealProbe, cause tpmProvisionCause) (tpmRecoveryAction, error) {
	switch probe {
	case tpmSealPresent:
		if cause == tpmCausePolicyDrift {
			return 0, ErrTPMSealPolicyDrift{}
		}
		return tpmRecoverSealPreserving, nil
	case tpmSealAbsent:
		return tpmRecoverFullProvision, nil
	default:
		return 0, ErrTPMSealStateUnknown{
			Detail: "TPM provisioning is required and the ESP artifact probe answered neither present nor absent"}
	}
}

// tpmIdentityCertStore is the narrow TPM surface the identity-completeness
// check reads. Both certificates must be present for the platform identity
// to count as provisioned.
type tpmIdentityCertStore interface {
	IAKCertificate() (*x509.Certificate, error)
	IDevIDCertificate() (*x509.Certificate, error)
}

// platformIdentityComplete reports whether the platform's device identity
// is fully provisioned: both the IAK and IDevID certificates are readable
// from the TPM certificate store. Bare handles without certificates — a
// firstboot install adopted by platformd — are incomplete, and InitTPM
// closes the gap with CompletePlatformIdentity (#61, round-4 review).
func platformIdentityComplete(tpm tpmIdentityCertStore) bool {
	if _, err := tpm.IAKCertificate(); err != nil {
		return false
	}
	if _, err := tpm.IDevIDCertificate(); err != nil {
		return false
	}
	return true
}

// tpmSealRepairer is the narrow TPM surface the seal-preserving repair
// drives. Deliberately EXCLUDES every clear-capable operation
// (FactoryResetWithClear, ForceClear, Provision) AND the evicting
// FactoryReset — go-xkms FactoryReset evicts every non-EK persistent
// handle, which would remove the Platform KeyStore SRK the seal is
// parented under — so the repair path cannot reach any of them by
// construction. The two PCR methods are read-and-restore only:
// IsPlatformPCRExtended reads the platform PCR, and CreatePlatformPolicy
// is invoked at most once, only on a demonstrably zero PCR.
type tpmSealRepairer interface {
	Install(soPIN xkmssdk.Password, opts *xkmssdk.InstallOptions) error
	IsPlatformPCRExtended() (bool, error)
	CreatePlatformPolicy() error
}

// sealPreservingTPMRepair recovers a TPM that needs provisioning while a
// TPM-sealed LUKS unlock exists on the ESP. It never clears and never
// evicts: the idempotent Install creates only what is missing (with
// hierarchy auth left untouched — nil soPIN), and every existing
// persistent object — above all the Platform KeyStore SRK the seal is
// parented under — is left exactly where it is. A missing Platform SRK is
// recreated later by InitPlatformKeyStore through the pkg/platform
// keychain (probe → InitializeWithDefaults), the same path firstboot and
// normal startup use.
//
// The platform PCR is handled OUTSIDE Install: a PCR extension is
// irreversible for the rest of the boot, and by the time this repair runs
// OpenTPM has already restored a zero platform PCR with the golden
// measurement. Requesting PlatformPolicy from Install would extend a
// second time, silently leaving the existing Platform SRK's PCR policy
// branch unsatisfiable — the exact corruption this gate exists to
// prevent. The repair therefore extends exactly once, only when the PCR
// is demonstrably still zero, and refuses to guess when its state cannot
// be read.
func sealPreservingTPMRepair(tpm tpmSealRepairer, logger *logging.Logger) error {
	logger.Warn("TPM provisioning required, but a TPM-sealed LUKS unlock exists on the ESP — " +
		"running seal-preserving repair (idempotent install only; no clear, no evict, no PPI escalation)")

	extended, err := tpm.IsPlatformPCRExtended()
	if err != nil {
		return &WrappedError{
			Msg: "seal-preserving TPM repair: platform PCR state indeterminable, " +
				"refusing to risk a double extension", Err: err}
	}
	if !extended {
		logger.Info("seal-preserving repair: platform PCR still zero — restoring golden measurements once")
		if err := tpm.CreatePlatformPolicy(); err != nil {
			return &WrappedError{Msg: "seal-preserving TPM repair: platform policy restore failed", Err: err}
		}
	}

	if err := tpm.Install(nil, &xkmssdk.InstallOptions{
		EK:     true,
		SSRK:   true,
		IAK:    true,
		IDevID: true,
	}); err != nil {
		if !errors.Is(err, xkmssdk.ErrTPMEndorsementCertNotFound) {
			return &WrappedError{Msg: "seal-preserving TPM repair failed", Err: err}
		}
		logger.Warn("EK certificate not found during seal-preserving repair (expected for swtpm)")
	}
	return nil
}
