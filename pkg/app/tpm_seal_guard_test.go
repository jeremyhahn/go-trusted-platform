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

package app

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestProbeTPMSealArtifacts asserts the seal probe (#61) answers
// tri-state: any artifact — even a torn half — is PRESENT, absence is
// answered only when the ESP is demonstrably mounted and the artifacts
// demonstrably do not exist, and everything else — an unmounted ESP, an
// unreadable path or mount table — is INDETERMINATE, never a guess in
// either direction: clearing would strand a real seal, and treating
// indeterminate as present would silently substitute partial repair for
// full provisioning (round-4 review).
func TestProbeTPMSealArtifacts(t *testing.T) {
	restorePaths := tpmSealArtifactPaths
	restoreMounts := tpmSealMountsFile
	restoreMP := tpmSealESPMountPoint
	defer func() {
		tpmSealArtifactPaths = restorePaths
		tpmSealMountsFile = restoreMounts
		tpmSealESPMountPoint = restoreMP
	}()

	dir := t.TempDir()
	pub := filepath.Join(dir, "seal-platform.pub")
	priv := filepath.Join(dir, "seal-platform.priv")
	tpmSealArtifactPaths = []string{pub, priv}
	tpmSealESPMountPoint = dir

	mounted := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mounted, []byte("/dev/sda1 "+dir+" vfat rw 0 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	notMounted := filepath.Join(dir, "mounts-empty")
	if err := os.WriteFile(notMounted, []byte("/dev/sda2 / ext4 rw 0 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The verified-ESP marker: every ESP this platform booted from carries
	// the EFI/ directory.
	if err := os.MkdirAll(filepath.Join(dir, "EFI"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("verified mounted ESP with no artifacts is absent", func(t *testing.T) {
		tpmSealMountsFile = mounted
		if got := probeTPMSealArtifacts(); got != tpmSealAbsent {
			t.Fatalf("probe = %v, want absent for a verified ESP without artifacts", got)
		}
	})

	t.Run("unmounted ESP is indeterminate", func(t *testing.T) {
		tpmSealMountsFile = notMounted
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — an unmounted ESP proves nothing and must be indeterminate", got)
		}
	})

	t.Run("a tmpfs at the mount point is indeterminate", func(t *testing.T) {
		// An unrelated filesystem mounted at /boot/efi must never make
		// the artifacts' absence look like proof (round-5 review).
		imposter := filepath.Join(dir, "mounts-tmpfs")
		if err := os.WriteFile(imposter, []byte("tmpfs "+dir+" tmpfs rw 0 0\n"), 0644); err != nil {
			t.Fatal(err)
		}
		tpmSealMountsFile = imposter
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — a non-ESP filesystem at the mount point must be indeterminate", got)
		}
	})

	t.Run("a non-vfat filesystem at the mount point is indeterminate", func(t *testing.T) {
		imposter := filepath.Join(dir, "mounts-ext4")
		if err := os.WriteFile(imposter, []byte("/dev/sda9 "+dir+" ext4 rw 0 0\n"), 0644); err != nil {
			t.Fatal(err)
		}
		tpmSealMountsFile = imposter
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — a non-vfat filesystem cannot be the ESP and must be indeterminate", got)
		}
	})

	t.Run("a vfat mount without the EFI directory is indeterminate", func(t *testing.T) {
		bare := filepath.Join(dir, "bare-esp")
		if err := os.MkdirAll(bare, 0755); err != nil {
			t.Fatal(err)
		}
		bareMounts := filepath.Join(dir, "mounts-bare")
		if err := os.WriteFile(bareMounts, []byte("/dev/sda1 "+bare+" vfat rw 0 0\n"), 0644); err != nil {
			t.Fatal(err)
		}
		restoreMP2 := tpmSealESPMountPoint
		tpmSealESPMountPoint = bare
		tpmSealMountsFile = bareMounts
		defer func() { tpmSealESPMountPoint = restoreMP2 }()
		// Artifact paths still point at the original dir — not-exist there,
		// so the answer hinges on ESP verification alone.
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — a vfat mount without EFI/ is not a booted ESP and must be indeterminate", got)
		}
	})

	t.Run("unreadable mount table is indeterminate", func(t *testing.T) {
		tpmSealMountsFile = filepath.Join(dir, "does-not-exist")
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — an unreadable mount table must be indeterminate", got)
		}
	})

	t.Run("a single torn artifact counts as present", func(t *testing.T) {
		tpmSealMountsFile = mounted
		if err := os.WriteFile(priv, []byte("blob"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(priv)
		if got := probeTPMSealArtifacts(); got != tpmSealPresent {
			t.Fatalf("probe = %v — a single (torn) artifact must still count as present", got)
		}
	})

	t.Run("stat error other than not-exist is indeterminate", func(t *testing.T) {
		tpmSealMountsFile = mounted
		// An intermediate path component that is a regular FILE makes
		// os.Stat fail with ENOTDIR — unlike a chmod-0000 directory,
		// this holds when the tests run as root (containers, CI).
		notADir := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(notADir, []byte("file, not directory"), 0644); err != nil {
			t.Fatal(err)
		}
		tpmSealArtifactPaths = []string{filepath.Join(notADir, "seal-platform.pub")}
		defer func() { tpmSealArtifactPaths = []string{pub, priv} }()
		if got := probeTPMSealArtifacts(); got != tpmSealIndeterminate {
			t.Fatalf("probe = %v — an ENOTDIR on the artifact path must be indeterminate", got)
		}
	})
}

// TestErrTPMSealStateUnknown asserts the indeterminate-probe error names
// the mount point the operator must make readable, with and without
// detail.
func TestErrTPMSealStateUnknown(t *testing.T) {
	err := ErrTPMSealStateUnknown{}
	if !strings.Contains(err.Error(), tpmSealESPMountPoint) {
		t.Fatalf("error must name the ESP mount point: %v", err)
	}
	detailed := ErrTPMSealStateUnknown{Detail: "probe detail"}
	if !strings.Contains(detailed.Error(), "probe detail") {
		t.Fatalf("error must carry its detail: %v", detailed)
	}
}

// TestResolveTPMRecovery asserts the startup recovery decision (rounds 4
// and 7): a proven seal with a repairable cause gets the seal-preserving
// repair, a proven seal-free node gets full destructive provisioning
// regardless of cause, and the two irreparable situations are typed
// startup errors — an indeterminate probe, and Platform SRK policy drift
// beside a present seal, which the install-only repair cannot fix without
// destroying the seal parent.
func TestResolveTPMRecovery(t *testing.T) {
	if action, err := resolveTPMRecovery(tpmSealPresent, tpmCauseUnprovisioned); err != nil || action != tpmRecoverSealPreserving {
		t.Fatalf("present/unprovisioned: action=%v err=%v, want seal-preserving repair", action, err)
	}
	if action, err := resolveTPMRecovery(tpmSealAbsent, tpmCauseUnprovisioned); err != nil || action != tpmRecoverFullProvision {
		t.Fatalf("absent/unprovisioned: action=%v err=%v, want full provisioning", action, err)
	}
	if action, err := resolveTPMRecovery(tpmSealAbsent, tpmCausePolicyDrift); err != nil || action != tpmRecoverFullProvision {
		t.Fatalf("absent/drift: action=%v err=%v — no seal to preserve, full provisioning rebuilds the SRK", action, err)
	}

	t.Run("policy drift beside a present seal is a typed error", func(t *testing.T) {
		_, err := resolveTPMRecovery(tpmSealPresent, tpmCausePolicyDrift)
		var drift ErrTPMSealPolicyDrift
		if !errors.As(err, &drift) {
			t.Fatalf("present/drift: error = %v, want ErrTPMSealPolicyDrift — the repair cannot "+
				"recreate the seal parent, so continuing would adopt an unusable SRK", err)
		}
		if !strings.Contains(err.Error(), tpmSealArtifactPaths[0]) {
			t.Fatalf("the error must name the seal artifacts the operator can remove: %v", err)
		}
	})

	t.Run("indeterminate probe is a typed error for every cause", func(t *testing.T) {
		for _, cause := range []tpmProvisionCause{tpmCauseUnprovisioned, tpmCausePolicyDrift} {
			_, err := resolveTPMRecovery(tpmSealIndeterminate, cause)
			var unknown ErrTPMSealStateUnknown
			if !errors.As(err, &unknown) {
				t.Fatalf("indeterminate/cause=%v: error = %v, want ErrTPMSealStateUnknown", cause, err)
			}
		}
	})
}

// fakeIdentityCertStore scripts the TPM certificate store reads behind the
// identity-completeness check.
type fakeIdentityCertStore struct {
	iakErr    error
	idevidErr error
}

func (f *fakeIdentityCertStore) IAKCertificate() (*x509.Certificate, error) {
	if f.iakErr != nil {
		return nil, f.iakErr
	}
	return &x509.Certificate{}, nil
}

func (f *fakeIdentityCertStore) IDevIDCertificate() (*x509.Certificate, error) {
	if f.idevidErr != nil {
		return nil, f.idevidErr
	}
	return &x509.Certificate{}, nil
}

// TestPlatformIdentityComplete asserts identity is complete only when BOTH
// the IAK and IDevID certificates are readable: firstboot-created handles
// without certificates must report incomplete, which is what routes an
// adopted TPM through CompletePlatformIdentity — certificate issuance and
// enrollment without any clear (round-4 review).
func TestPlatformIdentityComplete(t *testing.T) {
	if !platformIdentityComplete(&fakeIdentityCertStore{}) {
		t.Fatal("both certificates readable must report complete")
	}
	if platformIdentityComplete(&fakeIdentityCertStore{iakErr: context.DeadlineExceeded}) {
		t.Fatal("a missing IAK certificate must report incomplete")
	}
	if platformIdentityComplete(&fakeIdentityCertStore{idevidErr: context.DeadlineExceeded}) {
		t.Fatal("a missing IDevID certificate must report incomplete")
	}
}

// fakeSealRepairTPM records repair calls and models the platform PCR as
// the stateful, irreversible register it is: CreatePlatformPolicy flips
// pcrExtended and increments extensions, so a repair that extends an
// already-extended PCR is detectable. It deliberately implements ONLY
// tpmSealRepairer — the compiler proves the repair path cannot invoke a
// clear-capable operation (FactoryResetWithClear, ForceClear, Provision)
// NOR the Platform-SRK-evicting FactoryReset, which is the #61 review
// contract: the seal parent at 0x81000002 must survive the repair.
type fakeSealRepairTPM struct {
	installs    int
	instErr     error
	opts        *xkmssdk.InstallOptions
	pcrExtended bool
	pcrErr      error
	extensions  int
	policyErr   error
}

func (f *fakeSealRepairTPM) Install(soPIN xkmssdk.Password, opts *xkmssdk.InstallOptions) error {
	f.installs++
	f.opts = opts
	if soPIN != nil {
		panic("seal-preserving repair must never set hierarchy auth")
	}
	if opts != nil && opts.PlatformPolicy {
		panic("seal-preserving repair must never request PlatformPolicy from Install — " +
			"CreatePlatformPolicy extends the platform PCR unconditionally")
	}
	return f.instErr
}

func (f *fakeSealRepairTPM) IsPlatformPCRExtended() (bool, error) {
	return f.pcrExtended, f.pcrErr
}

func (f *fakeSealRepairTPM) CreatePlatformPolicy() error {
	if f.policyErr != nil {
		return f.policyErr
	}
	f.extensions++
	f.pcrExtended = true
	return nil
}

// TestSealPreservingTPMRepair asserts the repair path is install-only —
// no clear-capable operation and no evict (both excluded from the
// interface, so the seal's Platform SRK parent survives by construction) —
// extends the platform PCR at most once and only from zero (an
// already-extended PCR would otherwise leave the existing Platform SRK's
// PCR policy branch unsatisfiable for the rest of the boot), treats a
// missing EK certificate as non-fatal, and fails typed on real errors.
func TestSealPreservingTPMRepair(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("already-extended PCR is never extended again", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{pcrExtended: true}
		if err := sealPreservingTPMRepair(tpm, logger); err != nil {
			t.Fatalf("repair error = %v", err)
		}
		if tpm.extensions != 0 {
			t.Fatalf("extensions=%d, want 0 — the Platform SRK policy was created against "+
				"the once-extended value and must remain authorizable", tpm.extensions)
		}
		if tpm.installs != 1 {
			t.Fatalf("installs=%d, want 1", tpm.installs)
		}
		if tpm.opts == nil || !tpm.opts.EK || !tpm.opts.SSRK || !tpm.opts.IAK || !tpm.opts.IDevID {
			t.Fatalf("install options must ensure the full platform: %+v", tpm.opts)
		}
		if tpm.opts.PlatformPolicy {
			t.Fatal("install options must not request PlatformPolicy")
		}
	})

	t.Run("zero PCR is extended exactly once", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{}
		if err := sealPreservingTPMRepair(tpm, logger); err != nil {
			t.Fatalf("repair error = %v", err)
		}
		if tpm.extensions != 1 {
			t.Fatalf("extensions=%d, want exactly 1", tpm.extensions)
		}
		if tpm.installs != 1 {
			t.Fatalf("installs=%d, want 1", tpm.installs)
		}
	})

	t.Run("indeterminable PCR state fails typed without touching the TPM", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{pcrErr: context.DeadlineExceeded}
		if err := sealPreservingTPMRepair(tpm, logger); err == nil {
			t.Fatal("expected error")
		}
		if tpm.extensions != 0 || tpm.installs != 0 {
			t.Fatalf("extensions=%d installs=%d, want 0/0 — never guess with an irreversible extension",
				tpm.extensions, tpm.installs)
		}
	})

	t.Run("policy restore failure is a typed error and blocks install", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{policyErr: context.DeadlineExceeded}
		if err := sealPreservingTPMRepair(tpm, logger); err == nil {
			t.Fatal("expected error")
		}
		if tpm.installs != 0 {
			t.Fatalf("installs=%d, want 0", tpm.installs)
		}
	})

	t.Run("missing EK certificate is non-fatal", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{instErr: xkmssdk.ErrTPMEndorsementCertNotFound, pcrExtended: true}
		if err := sealPreservingTPMRepair(tpm, logger); err != nil {
			t.Fatalf("repair error = %v", err)
		}
	})

	t.Run("real install failure is a typed error", func(t *testing.T) {
		tpm := &fakeSealRepairTPM{instErr: context.DeadlineExceeded, pcrExtended: true}
		if err := sealPreservingTPMRepair(tpm, logger); err == nil {
			t.Fatal("expected error")
		}
	})
}
