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

package installer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

const (
	disklessSetURL   = "http://192.0.2.10/media/aarch64-virt"
	signedRootHash   = "1111111111111111111111111111111111111111111111111111111111111111"
	attackerRootHash = "2222222222222222222222222222222222222222222222222222222222222222"
)

// disklessFixture is a media set's signed manifest and an installer whose
// UKI is signed by the DB key that signed it.
type disklessFixture struct {
	installer *installer
	manifest  disklessroot.Manifest
	dir       string
	signerUse int
	dbKey     *rsa.PrivateKey
	db        *x509.Certificate
}

func newDisklessFixture(t *testing.T) *disklessFixture {
	t.Helper()
	dbKey, db := secureboottest.KeyPair(t, "platform-secureboot-db")
	f := &disklessFixture{
		dbKey: dbKey,
		db:    db,
		dir:   t.TempDir(),
		manifest: disklessroot.Manifest{
			Version:    disklessroot.ManifestVersion,
			RootHash:   signedRootHash,
			Salt:       disklessroot.DeriveSalt(1700000000, "1.0.0-test"),
			RootFSSize: 8 * disklessroot.BlockSize,
			VeritySize: disklessroot.BlockSize,
		},
	}
	require.NoError(t, disklessroot.WriteSigned(f.dir, f.manifest, dbKey))
	f.installer = &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			OS: &OSConfig{},
			SecureBoot: &SecureBootConfig{
				Enabled:    true,
				ResignMode: SecureBootResignModeRemote,
				DB: SecureBootKeyRef{
					KeyConfig: common.KeyConfig{CN: "platform-secureboot-db", StoreType: "software"},
					KeyURI:    "kms://platform/secureboot/db",
				},
			},
		},
		resolveRemoteSigner: func(context.Context, *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
			f.signerUse++
			return dbKey, db, nil
		},
		disklessManifestDir: f.dir,
		// An efivarfs with nothing enrolled: the KMS certificate is the anchor.
		efivarsDir: t.TempDir(),
	}
	return f
}

// localKeysOnly leaves the fixture without a KMS: the DB key that signed the
// manifest is only on the node, as a file:// pair.
func (f *disklessFixture) localKeysOnly(t *testing.T) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(f.dbKey)
	require.NoError(t, err)
	keys := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(keys, "DB.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(keys, "DB.crt"), secureboottest.PEM(f.db), 0o644))
	f.installer.config.SecureBoot.ResignMode = ""
	f.installer.config.SecureBoot.DB.KeyURI = "file://" + filepath.Join(keys, "DB.key")
	f.installer.resolveRemoteSigner = nil
}

// enrollDB writes certs as the firmware's db.
func (f *disklessFixture) enrollDB(t *testing.T, certs ...*x509.Certificate) {
	t.Helper()
	lists := make([]*uefi.SignatureList, 0, len(certs))
	for _, cert := range certs {
		lists = append(lists, uefi.NewSignatureListFromCert(cert.Raw, uefi.TrustedPlatformGUID))
	}
	data := append([]byte{0x27, 0x00, 0x00, 0x00}, uefi.ConcatSignatureLists(lists...)...)
	require.NoError(t, os.WriteFile(f.dbVariable(), data, 0o644))
}

func (f *disklessFixture) dbVariable() string {
	return filepath.Join(f.installer.efivarsDir, "db-"+strings.ToLower(uefi.EFIImageSecurityDatabase.String()))
}

func (f *disklessFixture) wantArgs(t *testing.T) []string {
	t.Helper()
	params, err := disklessroot.NewBootParams(f.manifest, disklessSetURL)
	require.NoError(t, err)
	return params.Args()
}

func TestDisklessCmdlineParams_FromTheSignedManifest(t *testing.T) {
	f := newDisklessFixture(t)
	live := "BOOT_IMAGE=vmlinuz-virt ip=dhcp platform_boot_model=diskless platform_bin_url=" + disklessSetURL + "/"

	args, err := f.installer.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)
	assert.Equal(t, f.wantArgs(t), args)
	assert.Contains(t, args, disklessroot.ParamRootHash+"="+signedRootHash)
	assert.Contains(t, args, disklessroot.ParamRootFSURL+"="+disklessSetURL+"/"+disklessroot.RootFSFile)
}

// TestDisklessCmdlineParams_TamperedCmdlineCannotChangeTheRoot: whatever a
// boot server or iPXE script writes on the installer's command line, the
// signed UKI names the root the manifest's signer endorsed.
func TestDisklessCmdlineParams_TamperedCmdlineCannotChangeTheRoot(t *testing.T) {
	f := newDisklessFixture(t)
	live := strings.Join([]string{
		"platform_boot_model=diskless",
		"platform_bin_url=" + disklessSetURL,
		disklessroot.ParamRootHash + "=" + attackerRootHash,
		disklessroot.ParamVeritySalt + "=" + attackerRootHash,
		disklessroot.ParamRootFSSize + "=4096",
		"roothash=" + attackerRootHash,
	}, " ")

	args, err := f.installer.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)
	assert.Equal(t, f.wantArgs(t), args)
	assert.NotContains(t, strings.Join(args, " "), attackerRootHash)
}

// TestDisklessCmdlineParams_TamperedManifestIsRefused: the manifest travels
// over the same network, so an edited one, or one signed by any other key,
// stops the install rather than signing a root into the UKI.
func TestDisklessCmdlineParams_TamperedManifestIsRefused(t *testing.T) {
	live := "platform_boot_model=diskless platform_bin_url=" + disklessSetURL

	f := newDisklessFixture(t)
	path := filepath.Join(f.dir, disklessroot.ManifestFile)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), signedRootHash, attackerRootHash)), 0o644))
	_, err = f.installer.disklessCmdlineParams(context.Background(), live)
	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Equal(t, ErrorTypeUKIBuild, installErr.Type)

	f = newDisklessFixture(t)
	otherKey, _ := secureboottest.KeyPair(t, "other")
	require.NoError(t, disklessroot.WriteSigned(f.dir, f.manifest, otherKey))
	_, err = f.installer.disklessCmdlineParams(context.Background(), live)
	require.ErrorAs(t, err, &installErr)
}

// TestDisklessCmdlineParams_DiskNode: a node the boot server did not mark
// diskless gets no root parameters, however many stray ones it carries, and
// no Secure Boot signer is resolved for it.
func TestDisklessCmdlineParams_DiskNode(t *testing.T) {
	f := newDisklessFixture(t)
	live := "platform_bin_url=" + disklessSetURL + " " + disklessroot.ParamRootHash + "=" + attackerRootHash

	args, err := f.installer.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)
	assert.Empty(t, args)
	assert.Zero(t, f.signerUse)
}

var encryptedLVMDisk = &DiskInfo{
	RootPartition:  "/dev/vda3",
	MappedDevice:   "/dev/mapper/cryptroot",
	LUKSUUID:       "5b1c7a52-3d4e-4f60-8a71-92b3c4d5e6f7",
	LVMDevice:      "/dev/platform/root",
	LVMVolumeGroup: "platform",
}

// TestUKIRootCmdlineParams_DiskNodeStillUnlocksLUKS: a disk node's UKI names
// its LUKS and LVM root exactly as before, and nothing of the diskless path.
func TestUKIRootCmdlineParams_DiskNodeStillUnlocksLUKS(t *testing.T) {
	f := newDisklessFixture(t)
	live := "platform_bin_url=" + disklessSetURL + " " + disklessroot.ParamRootHash + "=" + attackerRootHash
	diskless, err := f.installer.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)

	args := f.installer.ukiRootCmdlineParams(encryptedLVMDisk, diskless)
	assert.Equal(t, []string{
		"root=/dev/platform/root",
		"rd.luks.uuid=5b1c7a52-3d4e-4f60-8a71-92b3c4d5e6f7",
		"rd.luks.name=5b1c7a52-3d4e-4f60-8a71-92b3c4d5e6f7=cryptroot",
		"rd.lvm=1",
		"rd.lvm.vg=platform",
		"rootfstype=ext4",
	}, args)
	assert.NotContains(t, strings.Join(args, " "), "platform_")
}

func TestUKIRootCmdlineParams_DiskNodeVariants(t *testing.T) {
	f := newDisklessFixture(t)
	f.installer.config.Disk = &DiskConfig{Encryption: &EncryptionConfig{MappedName: "platform-root"}}

	assert.Equal(t, []string{"root=/dev/mapper/platform-root", "rd.luks.name=platform-root", "rootfstype=ext4"},
		f.installer.ukiRootCmdlineParams(&DiskInfo{RootPartition: "/dev/vda3", MappedDevice: "/dev/mapper/platform-root"}, nil),
		"a LUKS root without a UUID is named by its mapping")
	assert.Equal(t, []string{"root=/dev/vda3", "rootfstype=ext4"},
		f.installer.ukiRootCmdlineParams(&DiskInfo{RootPartition: "/dev/vda3"}, nil),
		"a plain root needs no unlock")
}

// TestUKIRootCmdlineParams_DisklessNodeHasNoLocalRoot: a diskless node's UKI
// names only the verified image, so dracut neither waits for nor unlocks a
// local root device it is not booting.
func TestUKIRootCmdlineParams_DisklessNodeHasNoLocalRoot(t *testing.T) {
	f := newDisklessFixture(t)
	live := "platform_boot_model=diskless platform_bin_url=" + disklessSetURL
	diskless, err := f.installer.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)

	args := f.installer.ukiRootCmdlineParams(encryptedLVMDisk, diskless)
	assert.Equal(t, f.wantArgs(t), args)
	joined := strings.Join(args, " ")
	for _, local := range []string{"root=", "rd.luks", "rd.lvm", "rootfstype="} {
		assert.NotContains(t, " "+joined, " "+local)
	}
}

func TestDisklessCmdlineParams_Failures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		live  string
		setup func(f *disklessFixture)
	}{
		{name: "an unknown boot model", live: "platform_boot_model=nbd platform_bin_url=" + disklessSetURL},
		// The installer has no nbd target yet: a diskless-nbd node fails
		// closed instead of installing to whatever local disk it has.
		{name: "a diskless-nbd node", live: "platform_boot_model=diskless-nbd platform_bin_url=" + disklessSetURL},
		{name: "the boot model twice", live: "platform_boot_model=diskless platform_boot_model=diskless platform_bin_url=" + disklessSetURL},
		{name: "no media set URL", live: "platform_boot_model=diskless"},
		{name: "a media set URL that is not http", live: "platform_boot_model=diskless platform_bin_url=tftp://192.0.2.10/set"},
		{name: "no manifest", live: "platform_boot_model=diskless platform_bin_url=" + disklessSetURL, setup: func(f *disklessFixture) {
			f.installer.disklessManifestDir = filepath.Join(f.dir, "missing")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDisklessFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			args, err := f.installer.disklessCmdlineParams(context.Background(), tc.live)
			var installErr *InstallerError
			require.ErrorAs(t, err, &installErr)
			assert.Equal(t, ErrorTypeUKIBuild, installErr.Type)
			assert.Empty(t, args)
		})
	}
}

func TestDisklessBootParams_NeedsAnAnchor(t *testing.T) {
	f := newDisklessFixture(t)
	_, err := disklessBootParams("platform_bin_url="+disklessSetURL, f.dir, nil)
	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Contains(t, installErr.Error(), "no pinned anchor")
}

// TestDisklessCmdlineParams_AnchoredInTheEnrolledDB: without a KMS the
// manifest verifies against a certificate the firmware has enrolled in db,
// whichever of them it is.
func TestDisklessCmdlineParams_AnchoredInTheEnrolledDB(t *testing.T) {
	f := newDisklessFixture(t)
	f.installer.resolveRemoteSigner = nil
	_, vendor := secureboottest.KeyPair(t, "vendor CA")
	f.enrollDB(t, vendor, f.db)

	args, err := f.installer.disklessCmdlineParams(context.Background(), "platform_boot_model=diskless platform_bin_url="+disklessSetURL)
	require.NoError(t, err)
	assert.Equal(t, f.wantArgs(t), args)
}

// TestDisklessCmdlineParams_OnlyThePlatformDBCertAnchors: the firmware db also
// holds the vendor's and Microsoft's certificates; a manifest one of those
// signed does not name a root.
func TestDisklessCmdlineParams_OnlyThePlatformDBCertAnchors(t *testing.T) {
	f := newDisklessFixture(t)
	f.installer.resolveRemoteSigner = nil
	vendorKey, vendor := secureboottest.KeyPair(t, "Vendor Signing CA")
	require.NoError(t, disklessroot.WriteSigned(f.dir, f.manifest, vendorKey))
	f.enrollDB(t, vendor, f.db)

	_, err := f.installer.disklessCmdlineParams(context.Background(), "platform_boot_model=diskless platform_bin_url="+disklessSetURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest")
}

func TestIsPlatformDBCert(t *testing.T) {
	cases := map[string]bool{
		"platform-secureboot-db":            true,
		"platform-secureboot-db - node-1":   true,
		"platform-secureboot-db-evil":       false,
		"Microsoft UEFI CA 2011":            false,
		"x platform-secureboot-db - node-1": false,
		"":                                  false,
	}
	for cn, want := range cases {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
		assert.Equal(t, want, isPlatformDBCert(cert, "platform-secureboot-db"), cn)
	}
	i := &installer{config: &Config{}}
	assert.Equal(t, defaultPlatformDBCommonName, i.platformDBCommonName())
}

// TestDisklessCmdlineParams_NeverTrustsLocalKeys: the DB pair the installer
// would sign the UKI with came over the same channel as the manifest (the
// install media, a file:// path) or would be generated on the spot, so it
// anchors nothing — even when it is the very key that signed the manifest.
func TestDisklessCmdlineParams_NeverTrustsLocalKeys(t *testing.T) {
	f := newDisklessFixture(t)
	f.localKeysOnly(t)
	_, staged, err := loadFileURISecureBootSigner(f.installer.config.SecureBoot)
	require.NoError(t, err)
	require.Equal(t, f.db.Raw, staged.Raw, "the local pair is the manifest's signer")

	args, err := f.installer.disklessCmdlineParams(context.Background(), "platform_boot_model=diskless platform_bin_url="+disklessSetURL)
	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Contains(t, installErr.Error(), "no pinned anchor")
	assert.Empty(t, args)
}

func TestDisklessCmdlineParams_AnchorFailures(t *testing.T) {
	live := "platform_boot_model=diskless platform_bin_url=" + disklessSetURL
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *disklessFixture)
		want  string
	}{
		{name: "db enrolls only another signer", want: "manifest", setup: func(t *testing.T, f *disklessFixture) {
			f.localKeysOnly(t)
			_, other := secureboottest.KeyPair(t, "other")
			f.enrollDB(t, other)
		}},
		{name: "no efivarfs and no KMS", want: "no pinned anchor", setup: func(t *testing.T, f *disklessFixture) {
			f.localKeysOnly(t)
			f.installer.efivarsDir = filepath.Join(t.TempDir(), "missing")
		}},
		{name: "the KMS is unreachable and db is empty", want: "no pinned anchor", setup: func(_ *testing.T, f *disklessFixture) {
			f.installer.resolveRemoteSigner = func(context.Context, *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
				return nil, nil, ErrSecureBoot("remote sign: unreachable", nil)
			}
		}},
		{name: "db is malformed", want: "enrolled db", setup: func(t *testing.T, f *disklessFixture) {
			require.NoError(t, os.WriteFile(f.dbVariable(), []byte{0x27, 0x00, 0x00, 0x00, 0xDE, 0xAD}, 0o644))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDisklessFixture(t)
			tc.setup(t, f)
			args, err := f.installer.disklessCmdlineParams(context.Background(), live)
			var installErr *InstallerError
			require.ErrorAs(t, err, &installErr)
			assert.Equal(t, ErrorTypeUKIBuild, installErr.Type)
			assert.Contains(t, installErr.Error(), tc.want)
			assert.Empty(t, args)
		})
	}
}

// TestDisklessCmdlineParams_EitherAnchorSuffices: an unreachable KMS does not
// stop a node whose db anchors the manifest.
func TestDisklessCmdlineParams_EitherAnchorSuffices(t *testing.T) {
	f := newDisklessFixture(t)
	f.installer.resolveRemoteSigner = func(context.Context, *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
		return nil, nil, ErrSecureBoot("remote sign: unreachable", nil)
	}
	f.enrollDB(t, f.db)

	args, err := f.installer.disklessCmdlineParams(context.Background(), "platform_boot_model=diskless platform_bin_url="+disklessSetURL)
	require.NoError(t, err)
	assert.Equal(t, f.wantArgs(t), args)
}
