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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	libtpm2 "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The persistent handles of the #681 identity model, as the templates
// configure them.
const (
	testEKHandle     uint32 = 0x81010001
	testSSRKHandle   uint32 = 0x81000001
	testPSRKHandle   uint32 = 0x81000002
	testIAKHandle    uint32 = 0x81010002
	testIDevIDHandle uint32 = 0x81020000
)

func disklessTPMConfig() xkmssdk.TPMConfig {
	return xkmssdk.TPMConfig{
		EK:          &xkmssdk.EKConfig{Handle: testEKHandle},
		SSRK:        &xkmssdk.SRKConfig{Handle: testSSRKHandle},
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: testPSRKHandle},
		IAK:         &xkmssdk.IAKConfig{Handle: testIAKHandle},
		IDevID:      &xkmssdk.IDevIDConfig{Handle: testIDevIDHandle},
	}
}

// residentPublic is a public area with the given key role, built on the TCG
// ECC SRK template so it marshals into a valid Name.
func residentPublic(restricted, decrypt, sign bool) libtpm2.TPMTPublic {
	pub := libtpm2.ECCSRKTemplate
	pub.ObjectAttributes.Restricted = restricted
	pub.ObjectAttributes.Decrypt = decrypt
	pub.ObjectAttributes.SignEncrypt = sign
	return pub
}

// ekObject is an ECC endorsement key's public area holding key.
func ekObject(t *testing.T, key *ecdsa.PublicKey) libtpm2.TPMTPublic {
	return eccObject(t, key, true, true, false)
}

// eccObject is a resident P-256 key with the given role whose public area
// carries key. The point is split from the key's uncompressed encoding,
// 0x04 || X || Y.
func eccObject(t *testing.T, key *ecdsa.PublicKey, restricted, decrypt, sign bool) libtpm2.TPMTPublic {
	t.Helper()
	point, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	coordinate := (len(point) - 1) / 2
	pub := residentPublic(restricted, decrypt, sign)
	pub.Unique = libtpm2.NewTPMUPublicID(libtpm2.TPMAlgECC, &libtpm2.TPMSECCPoint{
		X: libtpm2.TPM2BECCParameter{Buffer: point[1 : 1+coordinate]},
		Y: libtpm2.TPM2BECCParameter{Buffer: point[1+coordinate:]},
	})
	return pub
}

// newEK is a fresh P-256 endorsement public key.
func newEK(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

// provisionedObjects is the full identity a provisioned TPM holds.
func provisionedObjects() map[libtpm2.TPMHandle]libtpm2.TPMTPublic {
	storage := residentPublic(true, true, false)
	return map[libtpm2.TPMHandle]libtpm2.TPMTPublic{
		libtpm2.TPMHandle(testEKHandle):     storage,
		libtpm2.TPMHandle(testSSRKHandle):   storage,
		libtpm2.TPMHandle(testPSRKHandle):   storage,
		libtpm2.TPMHandle(testIAKHandle):    residentPublic(true, false, true),
		libtpm2.TPMHandle(testIDevIDHandle): residentPublic(false, false, true),
	}
}

// strictDisklessTPM is a TPM whose persistent objects are a map. Every
// destructive operation is counted, and ForceClear fails the test outright:
// a diskless node has no persistent place for the escalation's loop guard.
// Methods it does not override panic through the nil embedded interface, so
// any other TPM call the code under test makes is a failure too.
type strictDisklessTPM struct {
	xkmssdk.TrustedPlatformModule
	t        *testing.T
	objects  map[libtpm2.TPMHandle]libtpm2.TPMTPublic
	readErr  error
	resetErr error
	// forged names the handles whose ReadPublic Name is not the Name of the
	// public area returned beside it.
	forged map[libtpm2.TPMHandle]bool
	// ek is the endorsement key this TPM's EK handle holds, generated on
	// first read when unset: the one thing two TPMs booting one image never
	// share.
	ek *ecdsa.PublicKey
	// provisionOK lets Provision succeed, so first provisioning carries on
	// past it to the key store.
	provisionOK bool

	resets     int
	provisions int
}

// errProvisionReached stops ProvisionPlatform after TPM.Provision: what
// follows it (key store, CA, enrollment) is not the subject of these tests.
var errProvisionReached = errors.New("test: TPM.Provision reached")

func (f *strictDisklessTPM) ReadHandle(handle libtpm2.TPMHandle) (libtpm2.TPM2BName, libtpm2.TPMTPublic, error) {
	if f.readErr != nil {
		return libtpm2.TPM2BName{}, libtpm2.TPMTPublic{}, f.readErr
	}
	pub, ok := f.objects[handle]
	if !ok {
		// What a TPM answers TPM2_ReadPublic for an empty persistent handle.
		return libtpm2.TPM2BName{}, libtpm2.TPMTPublic{}, libtpm2.TPMRC(0x18b)
	}
	if handle == libtpm2.TPMHandle(testEKHandle) {
		if f.ek == nil {
			f.ek = newEK(f.t)
		}
		pub = ekObject(f.t, f.ek)
	}
	name, err := libtpm2.ObjectName(&pub)
	if err != nil {
		f.t.Fatalf("ObjectName: %v", err)
	}
	if f.forged[handle] {
		forged := append([]byte(nil), name.Buffer...)
		forged[len(forged)-1] ^= 0xff
		return libtpm2.TPM2BName{Buffer: forged}, pub, nil
	}
	return *name, pub, nil
}

func (f *strictDisklessTPM) FactoryResetWithClear(ownerAuth []byte) error {
	if ownerAuth != nil {
		f.t.Fatal("FactoryResetWithClear must use the empty lockout auth of a fresh TPM")
	}
	f.resets++
	return f.resetErr
}

func (f *strictDisklessTPM) Provision(soPIN xkmssdk.Password) error {
	f.provisions++
	f.objects = provisionedObjects()
	if f.provisionOK {
		return nil
	}
	return errProvisionReached
}

func (f *strictDisklessTPM) ForceClear() error {
	f.t.Fatal("ForceClear on a diskless node: the PPI escalation's loop guard cannot persist")
	return nil
}

func (f *strictDisklessTPM) Clear(lockoutAuth []byte) error {
	f.t.Fatal("Clear on a diskless node")
	return nil
}

func (f *strictDisklessTPM) FactoryReset(ownerAuth []byte) error {
	f.t.Fatal("FactoryReset on a diskless node")
	return nil
}

func disklessApp(tpm *strictDisklessTPM) *App {
	return &App{
		Logger:    logging.DefaultLogger(),
		TPM:       tpm,
		TPMConfig: disklessTPMConfig(),
	}
}

// TestBootsDiskless asserts platformd takes the boot model from the kernel
// command line the signed UKI carried, and refuses to guess when it cannot
// read one.
func TestBootsDiskless(t *testing.T) {
	restore := disklessCmdlinePath
	defer func() { disklessCmdlinePath = restore }()
	dir := t.TempDir()

	write := func(t *testing.T, cmdline string) {
		t.Helper()
		disklessCmdlinePath = filepath.Join(dir, "cmdline")
		if err := os.WriteFile(disklessCmdlinePath, []byte(cmdline), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("diskless model", func(t *testing.T) {
		write(t, "console=ttyS0 platform_boot_model=diskless quiet\n")
		diskless, err := bootsDiskless()
		if err != nil || !diskless {
			t.Fatalf("bootsDiskless() = %v, %v; want true, nil", diskless, err)
		}
	})

	t.Run("disk node", func(t *testing.T) {
		write(t, "root=/dev/mapper/vg-root rd.luks.uuid=abc quiet\n")
		diskless, err := bootsDiskless()
		if err != nil || diskless {
			t.Fatalf("bootsDiskless() = %v, %v; want false, nil", diskless, err)
		}
	})

	t.Run("duplicated boot model is refused", func(t *testing.T) {
		write(t, "platform_boot_model=diskless platform_boot_model=disk\n")
		_, err := bootsDiskless()
		var unreadable *ErrBootModelUnreadable
		if !errors.As(err, &unreadable) {
			t.Fatalf("err = %v, want *ErrBootModelUnreadable", err)
		}
	})

	t.Run("missing command line is refused", func(t *testing.T) {
		disklessCmdlinePath = filepath.Join(dir, "absent")
		_, err := bootsDiskless()
		var unreadable *ErrBootModelUnreadable
		if !errors.As(err, &unreadable) || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want *ErrBootModelUnreadable wrapping ErrNotExist", err)
		}
	})
}

// TestResidentTPMIdentity asserts a TPM counts as provisioned only when every
// identity handle holds an object of the role the #681 model gives it, under
// the Name of its public area; as unprovisioned only when every handle is
// empty; and that anything between the two is refused, naming the handles.
func TestResidentTPMIdentity(t *testing.T) {
	cfg := disklessTPMConfig()

	t.Run("full identity is resident", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, objects: provisionedObjects()}
		resident, err := residentTPMIdentity(tpm, &cfg)
		if err != nil || !resident {
			t.Fatalf("residentTPMIdentity = %v, %v; want true, nil", resident, err)
		}
	})

	t.Run("every handle empty means unprovisioned", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{}}
		resident, err := residentTPMIdentity(tpm, &cfg)
		if err != nil || resident {
			t.Fatalf("residentTPMIdentity = %v, %v; want false, nil", resident, err)
		}
	})

	// requirePartial asserts err is an *ErrTPMIdentityPartial naming exactly
	// the given empty and mismatched handles.
	requirePartial := func(t *testing.T, err error, empty, mismatched []uint32) {
		t.Helper()
		var partial *ErrTPMIdentityPartial
		if !errors.As(err, &partial) {
			t.Fatalf("err = %v, want *ErrTPMIdentityPartial", err)
		}
		if len(partial.Empty) != len(empty) || len(partial.Mismatched) != len(mismatched) {
			t.Fatalf("partial = %+v, want %d empty and %d mismatched", partial, len(empty), len(mismatched))
		}
		for _, handle := range empty {
			if !strings.Contains(err.Error(), fmt.Sprintf("0x%08X", handle)) {
				t.Fatalf("error %q does not name empty handle 0x%08X", err, handle)
			}
		}
		for _, handle := range mismatched {
			if !strings.Contains(err.Error(), fmt.Sprintf("0x%08X", handle)) {
				t.Fatalf("error %q does not name mismatched handle 0x%08X", err, handle)
			}
		}
	}

	t.Run("each single missing handle fails closed", func(t *testing.T) {
		for handle := range provisionedObjects() {
			objects := provisionedObjects()
			delete(objects, handle)
			tpm := &strictDisklessTPM{t: t, objects: objects}
			_, err := residentTPMIdentity(tpm, &cfg)
			requirePartial(t, err, []uint32{uint32(handle)}, nil)
		}
	})

	t.Run("only the EK resident fails closed", func(t *testing.T) {
		// A TPM that kept its manufacturer EK but lost the rest is not empty.
		objects := map[libtpm2.TPMHandle]libtpm2.TPMTPublic{
			libtpm2.TPMHandle(testEKHandle): residentPublic(true, true, false),
		}
		tpm := &strictDisklessTPM{t: t, objects: objects}
		_, err := residentTPMIdentity(tpm, &cfg)
		requirePartial(t, err, []uint32{testSSRKHandle, testPSRKHandle, testIAKHandle, testIDevIDHandle}, nil)
	})

	t.Run("an object of the wrong role fails closed", func(t *testing.T) {
		objects := provisionedObjects()
		// A storage key where the IAK belongs: some other provisioning left it.
		objects[libtpm2.TPMHandle(testIAKHandle)] = residentPublic(true, true, false)
		tpm := &strictDisklessTPM{t: t, objects: objects}
		_, err := residentTPMIdentity(tpm, &cfg)
		requirePartial(t, err, nil, []uint32{testIAKHandle})
	})

	t.Run("a duplicable object fails closed", func(t *testing.T) {
		objects := provisionedObjects()
		idevid := objects[libtpm2.TPMHandle(testIDevIDHandle)]
		idevid.ObjectAttributes.FixedTPM = false
		objects[libtpm2.TPMHandle(testIDevIDHandle)] = idevid
		tpm := &strictDisklessTPM{t: t, objects: objects}
		_, err := residentTPMIdentity(tpm, &cfg)
		requirePartial(t, err, nil, []uint32{testIDevIDHandle})
	})

	t.Run("a Name that is not the public area's fails closed", func(t *testing.T) {
		tpm := &strictDisklessTPM{
			t:       t,
			objects: provisionedObjects(),
			forged:  map[libtpm2.TPMHandle]bool{libtpm2.TPMHandle(testSSRKHandle): true},
		}
		_, err := residentTPMIdentity(tpm, &cfg)
		requirePartial(t, err, nil, []uint32{testSSRKHandle})
	})

	t.Run("empty and mismatched handles are both named", func(t *testing.T) {
		objects := provisionedObjects()
		delete(objects, libtpm2.TPMHandle(testIDevIDHandle))
		objects[libtpm2.TPMHandle(testIAKHandle)] = residentPublic(true, true, false)
		tpm := &strictDisklessTPM{t: t, objects: objects}
		_, err := residentTPMIdentity(tpm, &cfg)
		requirePartial(t, err, []uint32{testIDevIDHandle}, []uint32{testIAKHandle})
	})

	t.Run("a read failure is an error, not an empty TPM", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, objects: provisionedObjects(), readErr: libtpm2.TPMRC(0x101)}
		_, err := residentTPMIdentity(tpm, &cfg)
		var unreadable *ErrTPMHandleUnreadable
		if !errors.As(err, &unreadable) {
			t.Fatalf("err = %v, want *ErrTPMHandleUnreadable", err)
		}
	})

	t.Run("an unconfigured handle is a configuration error", func(t *testing.T) {
		partial := disklessTPMConfig()
		partial.PlatformSRK.SRKHandle = 0
		tpm := &strictDisklessTPM{t: t, objects: provisionedObjects()}
		_, err := residentTPMIdentity(tpm, &partial)
		var unset *ErrTPMHandleUnset
		if !errors.As(err, &unset) || unset.Key != "platform-srk" {
			t.Fatalf("err = %v, want *ErrTPMHandleUnset for platform-srk", err)
		}

		partial = disklessTPMConfig()
		partial.IDevID = nil
		_, err = residentTPMIdentity(tpm, &partial)
		if !errors.As(err, &unset) || unset.Key != "idevid" {
			t.Fatalf("err = %v, want *ErrTPMHandleUnset for idevid", err)
		}
	})
}

// TestProvisionDisklessTPM asserts the per-boot TPM decision of a diskless
// node: a provisioned TPM is adopted untouched on every boot, and an
// unprovisioned one is provisioned exactly once.
func TestProvisionDisklessTPM(t *testing.T) {
	ctx := context.Background()
	soPIN := mustPassword(t, []byte("so-pin"))
	userPIN := mustPassword(t, []byte("user-pin"))

	t.Run("provisioned TPM is never reset or provisioned", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, objects: provisionedObjects()}
		app := disklessApp(tpm)
		for boot := 1; boot <= 3; boot++ {
			ran, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
			if err != nil || ran {
				t.Fatalf("boot %d: provisionDisklessTPM = %v, %v; want false, nil", boot, ran, err)
			}
		}
		if tpm.resets != 0 || tpm.provisions != 0 {
			t.Fatalf("resets=%d provisions=%d, want 0 and 0", tpm.resets, tpm.provisions)
		}
	})

	t.Run("unprovisioned TPM is provisioned once", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{}}
		app := disklessApp(tpm)
		_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		if !errors.Is(err, errProvisionReached) {
			t.Fatalf("first boot err = %v, want the provisioning run", err)
		}
		if tpm.resets != 1 || tpm.provisions != 1 {
			t.Fatalf("first boot: resets=%d provisions=%d, want 1 and 1", tpm.resets, tpm.provisions)
		}

		// The next boot finds the identity the first one left in the TPM.
		ran, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		if err != nil || ran {
			t.Fatalf("second boot: provisionDisklessTPM = %v, %v; want false, nil", ran, err)
		}
		if tpm.resets != 1 || tpm.provisions != 1 {
			t.Fatalf("second boot: resets=%d provisions=%d, want still 1 and 1", tpm.resets, tpm.provisions)
		}
	})

	t.Run("a refused reset provisions without the PPI escalation", func(t *testing.T) {
		tpm := &strictDisklessTPM{
			t:        t,
			objects:  map[libtpm2.TPMHandle]libtpm2.TPMTPublic{},
			resetErr: errors.New("TPM_RC_BAD_AUTH"),
		}
		app := disklessApp(tpm)
		_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		if !errors.Is(err, errProvisionReached) {
			t.Fatalf("err = %v, want the provisioning run", err)
		}
		if tpm.provisions != 1 {
			t.Fatalf("provisions=%d, want 1", tpm.provisions)
		}
	})

	t.Run("a partial identity is never cleared or provisioned", func(t *testing.T) {
		for handle := range provisionedObjects() {
			objects := provisionedObjects()
			delete(objects, handle)
			tpm := &strictDisklessTPM{t: t, objects: objects}
			app := disklessApp(tpm)
			_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
			var partial *ErrTPMIdentityPartial
			if !errors.As(err, &partial) {
				t.Fatalf("handle 0x%08X absent: err = %v, want *ErrTPMIdentityPartial", uint32(handle), err)
			}
			if tpm.resets != 0 || tpm.provisions != 0 {
				t.Fatalf("handle 0x%08X absent: resets=%d provisions=%d, want 0 and 0",
					uint32(handle), tpm.resets, tpm.provisions)
			}
			if len(tpm.objects) != len(provisionedObjects())-1 {
				t.Fatalf("handle 0x%08X absent: the TPM's objects changed", uint32(handle))
			}
		}
	})

	t.Run("a mismatched identity is never cleared or provisioned", func(t *testing.T) {
		objects := provisionedObjects()
		objects[libtpm2.TPMHandle(testIDevIDHandle)] = residentPublic(true, true, false)
		tpm := &strictDisklessTPM{t: t, objects: objects}
		app := disklessApp(tpm)
		_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		var partial *ErrTPMIdentityPartial
		if !errors.As(err, &partial) {
			t.Fatalf("err = %v, want *ErrTPMIdentityPartial", err)
		}
		if tpm.resets != 0 || tpm.provisions != 0 {
			t.Fatalf("resets=%d provisions=%d, want 0 and 0", tpm.resets, tpm.provisions)
		}
	})

	t.Run("a TPM that cannot be read is not provisioned", func(t *testing.T) {
		tpm := &strictDisklessTPM{t: t, readErr: libtpm2.TPMRC(0x101)}
		app := disklessApp(tpm)
		_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		var unreadable *ErrTPMHandleUnreadable
		if !errors.As(err, &unreadable) {
			t.Fatalf("err = %v, want *ErrTPMHandleUnreadable", err)
		}
		if tpm.resets != 0 || tpm.provisions != 0 {
			t.Fatalf("resets=%d provisions=%d, want 0 and 0", tpm.resets, tpm.provisions)
		}
	})
}

// imageApp is a diskless node booting the shared image: the hostname, TCG
// product serial and identity Common Names every node built from one media
// set carries.
func imageApp(tpm *strictDisklessTPM) *App {
	app := disklessApp(tpm)
	app.Hostname = "r640-compute"
	app.TPMConfig.IDevID.Serial = "DELL-R640-COMPUTE-01"
	app.TPMConfig.IDevID.CN = "r640-compute-idevid"
	app.TPMConfig.IAK.CN = "r640-compute-iak"
	return app
}

// TestApplyDisklessNodeIdentity asserts a diskless node is named after its
// TPM's EK, and that name replaces every identity the image carries.
func TestApplyDisklessNodeIdentity(t *testing.T) {
	t.Run("the EK names the node, not the image", func(t *testing.T) {
		ek := newEK(t)
		tpm := &strictDisklessTPM{t: t, objects: provisionedObjects(), ek: ek}
		app := imageApp(tpm)
		if err := app.applyDisklessNodeIdentity(); err != nil {
			t.Fatal(err)
		}
		want, err := entities.EKNodeIdentity(ek)
		if err != nil {
			t.Fatal(err)
		}
		if app.nodeIdentity != want || app.enrollmentName() != want {
			t.Fatalf("identity = %q, enrollment name %q; want %q", app.nodeIdentity, app.enrollmentName(), want)
		}
		if app.TPMConfig.IDevID.Serial != want ||
			app.TPMConfig.IDevID.CN != want+"-idevid" ||
			app.TPMConfig.IAK.CN != want+"-iak" {
			t.Fatalf("image identity not replaced: serial %q, IDevID CN %q, IAK CN %q",
				app.TPMConfig.IDevID.Serial, app.TPMConfig.IDevID.CN, app.TPMConfig.IAK.CN)
		}
		if app.Hostname != "r640-compute" {
			t.Fatalf("hostname = %q; the cosmetic hostname must be left alone", app.Hostname)
		}
	})

	t.Run("a disk node enrolls under its hostname", func(t *testing.T) {
		app := &App{Hostname: "node-1"}
		if app.enrollmentName() != "node-1" {
			t.Fatalf("enrollment name = %q, want the hostname", app.enrollmentName())
		}
	})

	failures := map[string]struct {
		tpm    func(t *testing.T) *strictDisklessTPM
		mutate func(*App)
	}{
		"an empty EK handle": {
			tpm: func(t *testing.T) *strictDisklessTPM {
				return &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{}}
			},
		},
		"an unreadable TPM": {
			tpm: func(t *testing.T) *strictDisklessTPM {
				return &strictDisklessTPM{t: t, readErr: libtpm2.TPMRC(0x101)}
			},
		},
		"no EK section": {
			tpm:    func(t *testing.T) *strictDisklessTPM { return &strictDisklessTPM{t: t, objects: provisionedObjects()} },
			mutate: func(a *App) { a.TPMConfig.EK = nil },
		},
		"no IDevID section": {
			tpm:    func(t *testing.T) *strictDisklessTPM { return &strictDisklessTPM{t: t, objects: provisionedObjects()} },
			mutate: func(a *App) { a.TPMConfig.IDevID = nil },
		},
	}
	for name, tc := range failures {
		t.Run(name, func(t *testing.T) {
			app := imageApp(tc.tpm(t))
			if tc.mutate != nil {
				tc.mutate(app)
			}
			err := app.applyDisklessNodeIdentity()
			var unavailable ErrDisklessIdentityUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrDisklessIdentityUnavailable", err)
			}
			if app.nodeIdentity != "" || app.enrollmentName() != "r640-compute" {
				t.Fatalf("a failed derivation left identity %q", app.nodeIdentity)
			}
		})
	}
}

func TestResidentPublicKey(t *testing.T) {
	key := newEK(t)
	tpm := &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{
		libtpm2.TPMHandle(testIDevIDHandle): eccObject(t, key, false, false, true),
	}}

	t.Run("reads the key persisted at the handle", func(t *testing.T) {
		pub, err := residentPublicKey(tpm, testIDevIDHandle)
		if err != nil {
			t.Fatalf("residentPublicKey: %v", err)
		}
		if !key.Equal(pub) {
			t.Fatalf("read %v, want the persisted key", pub)
		}
	})
	t.Run("an empty handle has no key", func(t *testing.T) {
		pub, err := residentPublicKey(tpm, testIAKHandle)
		if err == nil || pub != nil {
			t.Fatalf("got %v, %v; want no key and an error", pub, err)
		}
	})
	t.Run("an unreadable TPM has no key", func(t *testing.T) {
		readErr := errors.New("tpm unreachable")
		unreadable := &strictDisklessTPM{t: t, readErr: readErr}
		if _, err := residentPublicKey(unreadable, testIDevIDHandle); !errors.Is(err, readErr) {
			t.Fatalf("err = %v, want %v", err, readErr)
		}
	})
}

// TestDisklessNodesFromOneImage boots two nodes from the same image with
// different TPMs and asserts each claims its own identity: on first
// provisioning, before anything is enrolled, and on every boot after it.
func TestDisklessNodesFromOneImage(t *testing.T) {
	ctx := context.Background()
	soPIN := mustPassword(t, []byte("so-pin"))
	userPIN := mustPassword(t, []byte("user-pin"))

	// keyStoreUnreachable makes first provisioning stop at the platform key
	// store, the first step after the identity is derived: everything
	// enrollment does after it reads the identity this test asserts on.
	keyStoreUnreachable := func(t *testing.T, app *App) {
		blocker := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		app.PlatformDir = blocker
	}

	boot := func(t *testing.T, tpm *strictDisklessTPM, firstBoot bool) *App {
		t.Helper()
		app := imageApp(tpm)
		app.ACMEConfig = &trustedca.ACMEConfig{
			Client: &trustedca.ACMEClientYAMLConfig{DirectoryURL: "https://cp.example:8443/acme/directory"}}
		if firstBoot {
			keyStoreUnreachable(t, app)
		}
		_, err := app.provisionDisklessTPM(ctx, soPIN, userPIN, &AppInitParams{})
		if firstBoot {
			if err == nil || !strings.Contains(err.Error(), "storage backend") {
				t.Fatalf("first boot err = %v, want the key store step after the identity", err)
			}
		} else if err != nil {
			t.Fatalf("boot err = %v", err)
		}
		return app
	}

	nodeA := &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{}, provisionOK: true}
	nodeB := &strictDisklessTPM{t: t, objects: map[libtpm2.TPMHandle]libtpm2.TPMTPublic{}, provisionOK: true}

	firstA, firstB := boot(t, nodeA, true), boot(t, nodeB, true)
	againA, againB := boot(t, nodeA, false), boot(t, nodeB, false)

	for _, app := range []*App{firstA, firstB, againA, againB} {
		if !entities.IsEKNodeIdentity(app.nodeIdentity) {
			t.Fatalf("node identity %q is not EK-derived", app.nodeIdentity)
		}
	}
	if firstA.nodeIdentity == firstB.nodeIdentity {
		t.Fatalf("two TPMs booting one image both enroll as %q", firstA.nodeIdentity)
	}
	if firstA.TPMConfig.IDevID.Serial == firstB.TPMConfig.IDevID.Serial ||
		firstA.TPMConfig.IDevID.CN == firstB.TPMConfig.IDevID.CN ||
		firstA.TPMConfig.IAK.CN == firstB.TPMConfig.IAK.CN {
		t.Fatal("two TPMs booting one image request certificates for the same identity")
	}
	if againA.nodeIdentity != firstA.nodeIdentity || againB.nodeIdentity != firstB.nodeIdentity {
		t.Fatal("a node's identity changed between its first boot and the next")
	}

	targetA, err := againA.disklessBootTarget()
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := againB.disklessBootTarget()
	if err != nil {
		t.Fatal(err)
	}
	if targetA.identity != firstA.nodeIdentity || targetB.identity != firstB.nodeIdentity {
		t.Fatalf("recovery asks for %q and %q, not the enrolled identities", targetA.identity, targetB.identity)
	}
}

// TestErrDisklessIdentityUnavailable asserts the refusal names what the node
// is missing and why it does not mint the identity itself.
func TestErrDisklessIdentityUnavailable(t *testing.T) {
	cause := errors.New("connection refused")
	var err error = ErrDisklessIdentityUnavailable{Reason: "attested boot delivery failed", Cause: cause}

	msg := err.Error()
	for _, want := range []string{"§4d", "attested boot delivery failed", "connection refused"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error text %q does not name %q", msg, want)
		}
	}
	var target ErrDisklessIdentityUnavailable
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed for ErrDisklessIdentityUnavailable")
	}
	if !errors.Is(err, cause) {
		t.Fatal("the cause must stay reachable through Unwrap")
	}
	if strings.HasSuffix(ErrDisklessIdentityUnavailable{Reason: "r"}.Error(), ": ") {
		t.Fatal("a causeless error must not end in a dangling separator")
	}
}

func TestErrTPMIdentityPartial(t *testing.T) {
	err := &ErrTPMIdentityPartial{Empty: []string{"iak (0x81010002)"}}
	msg := err.Error()
	for _, want := range []string{"§4d", "refusing to clear", "empty: iak (0x81010002)"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error text %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, "mismatched") {
		t.Fatalf("error text %q names a mismatched set it does not have", msg)
	}

	err = &ErrTPMIdentityPartial{Mismatched: []string{"ek (0x81010001)", "ssrk (0x81000001)"}}
	msg = err.Error()
	if !strings.Contains(msg, "mismatched: ek (0x81010001), ssrk (0x81000001)") || strings.Contains(msg, "empty:") {
		t.Fatalf("error text %q does not name exactly the mismatched handles", msg)
	}
}
