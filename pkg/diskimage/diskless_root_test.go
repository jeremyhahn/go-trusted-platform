package diskimage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

const (
	testVerityRootHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testLoop           = "/dev/loop7"
	testEpoch          = int64(1700000000)
	// The scratch image's root partition: 1 MiB in, 8 MiB long.
	testRootStartLBA = 2048
	testRootSectors  = 16384
)

var testSalt = disklessroot.DeriveSalt(testEpoch, "1.0.0-test")

// disklessRunner stands in for the tools the in-container step runs. Mounting
// the root partition lays tree into the mount point; mksquashfs, unsquashfs and
// veritysetup produce what the real ones would.
type disklessRunner struct {
	calls []string
	// fail names a tool that fails.
	fail string
	// tree is what the mounted root partition holds, relative path to content.
	tree map[string]string
	// listing is what unsquashfs -l prints.
	listing string
	// squashSize is the size of the squashfs mksquashfs writes.
	squashSize int
	// verityOutput is what veritysetup format prints.
	verityOutput string
}

func newDisklessRunner() *disklessRunner {
	return &disklessRunner{
		tree:         map[string]string{"etc/fstab": "UUID=root / ext4 rw 0 1\n", "sbin/init": "busybox", "usr/bin/platformd": "elf"},
		listing:      "squashfs-root\nsquashfs-root/etc\nsquashfs-root/etc/fstab\nsquashfs-root/sbin/init\nsquashfs-root/usr/bin/platformd\n",
		squashSize:   2 * disklessroot.BlockSize,
		verityOutput: "VERITY header information for rootfs.verity\nRoot hash:      \t" + testVerityRootHash + "\n",
	}
}

func (r *disklessRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == r.fail {
		return []byte("boom"), errors.New("exit 1")
	}
	last := args[len(args)-1]
	switch name {
	case "mount":
		for rel, content := range r.tree {
			path := filepath.Join(last, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return nil, err
			}
		}
	case "mksquashfs":
		return nil, os.WriteFile(args[1], make([]byte, r.squashSize), 0o644)
	case "unsquashfs":
		return []byte(r.listing), nil
	case "veritysetup":
		if err := os.WriteFile(last, make([]byte, disklessroot.BlockSize), 0o644); err != nil {
			return nil, err
		}
		return []byte(r.verityOutput), nil
	}
	return nil, nil
}

// fakeAssemble writes a scratch image with an MBR (ESP, then the root) and
// records the configuration it was asked to install.
type fakeAssemble struct {
	cfg   *installer.Config
	parts int
	err   error
}

func (a *fakeAssemble) assemble(_ context.Context, opts AssembleOptions) (*AssembleResult, error) {
	a.cfg = opts.Config
	if a.err != nil {
		return nil, a.err
	}
	sector := make([]byte, sectorSize)
	sector[510], sector[511] = 0x55, 0xaa
	entries := []struct {
		kind           byte
		start, sectors uint32
	}{{0x0c, 2048, 2048}, {0x83, testRootStartLBA, testRootSectors}}
	for i, e := range entries[:a.parts] {
		entry := sector[446+16*i : 446+16*(i+1)]
		entry[4] = e.kind
		binary.LittleEndian.PutUint32(entry[8:12], e.start)
		binary.LittleEndian.PutUint32(entry[12:16], e.sectors)
	}
	return &AssembleResult{Image: opts.Output}, os.WriteFile(opts.Output, sector, 0o644)
}

func disklessOptions(t *testing.T, rec *disklessRunner, asm *fakeAssemble) DisklessRootOptions {
	t.Helper()
	return DisklessRootOptions{
		Config: &installer.Config{
			EnableTPMSealing: true,
			Disk:             &installer.DiskConfig{RootFilesystem: installer.FilesystemLVM, Encryption: &installer.EncryptionConfig{}},
		},
		SizeMB:          2048,
		WorkDir:         t.TempDir(),
		OutputDir:       t.TempDir(),
		SourceDateEpoch: testEpoch,
		Salt:            testSalt,
		Runner:          rec.run,
		assemble:        asm.assemble,
		allocateLoop:    func() (string, error) { return testLoop, nil },
	}
}

// expectedDisklessCalls is the exact tool sequence of a successful build.
func expectedDisklessCalls(opts DisklessRootOptions) []string {
	mountDir := filepath.Join(opts.WorkDir, "root")
	rootfs := filepath.Join(opts.OutputDir, disklessroot.RootFSFile)
	verity := filepath.Join(opts.OutputDir, disklessroot.VerityFile)
	return []string{
		"losetup --offset 1048576 --sizelimit 8388608 " + testLoop + " " + filepath.Join(opts.WorkDir, disklessImageFile),
		"mount -t ext4 " + testLoop + " " + mountDir,
		"mksquashfs " + mountDir + " " + rootfs + " -noappend -comp xz -reproducible -mkfs-time 1700000000 -all-time 1700000000",
		"umount " + mountDir,
		"losetup --detach " + testLoop,
		"unsquashfs -l " + rootfs,
		"veritysetup format --no-superblock --hash sha256 --data-block-size 4096 --hash-block-size 4096 --salt " + testSalt + " " + rootfs + " " + verity,
	}
}

func TestGenerateDisklessRootPacksTheInstalledRoot(t *testing.T) {
	rec, asm := newDisklessRunner(), &fakeAssemble{parts: 2}
	opts := disklessOptions(t, rec, asm)
	original := opts.Config.Disk
	res, err := GenerateDisklessRoot(context.Background(), opts)
	if err != nil {
		t.Fatalf("GenerateDisklessRoot: %v", err)
	}
	if !slices.Equal(rec.calls, expectedDisklessCalls(opts)) {
		t.Errorf("calls =\n%s\nwant\n%s", strings.Join(rec.calls, "\n"), strings.Join(expectedDisklessCalls(opts), "\n"))
	}
	want := disklessroot.Manifest{Version: disklessroot.ManifestVersion, RootHash: testVerityRootHash, Salt: testSalt, RootFSSize: 2 * disklessroot.BlockSize, VeritySize: disklessroot.BlockSize}
	if res.Manifest != want {
		t.Errorf("manifest = %+v, want %+v", res.Manifest, want)
	}
	if hash, err := os.ReadFile(filepath.Join(opts.OutputDir, DisklessRootHashFile)); err != nil || string(hash) != testVerityRootHash+"\n" {
		t.Errorf("root hash file = %q, %v", hash, err)
	}
	if fstab, err := os.ReadFile(filepath.Join(opts.WorkDir, "root", "etc", "fstab")); err != nil || string(fstab) != disklessFstab {
		t.Errorf("the packed root keeps the disk fstab: %q, %v", fstab, err)
	}
	if _, err := os.Stat(filepath.Join(opts.WorkDir, disklessImageFile)); !os.IsNotExist(err) {
		t.Errorf("the scratch image was left behind: %v", err)
	}
	// The install is the media's, unencrypted on ext4 with nothing sealed;
	// the caller's configuration is not touched.
	if asm.cfg.Disk.Encryption != nil || asm.cfg.Disk.RootFilesystem != installer.FilesystemExt4 || asm.cfg.EnableTPMSealing {
		t.Errorf("installed with %+v, sealing %v", asm.cfg.Disk, asm.cfg.EnableTPMSealing)
	}
	if original.Encryption == nil || original.RootFilesystem != installer.FilesystemLVM || !opts.Config.EnableTPMSealing {
		t.Errorf("the caller's configuration was modified: %+v", original)
	}
}

func TestGenerateDisklessRootIsDeterministic(t *testing.T) {
	// Two builds of the same release run the same commands with the same
	// salt and timestamps: the root hash is a function of the tree.
	var runs [][]string
	var manifests []disklessroot.Manifest
	for range 2 {
		rec := newDisklessRunner()
		rec.tree["etc/shadow"] = usableShadow
		opts := disklessOptions(t, rec, &fakeAssemble{parts: 2})
		base := t.TempDir()
		opts.WorkDir, opts.OutputDir = filepath.Join(base, "work"), filepath.Join(base, "out")
		res, err := GenerateDisklessRoot(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, res.Manifest)
		calls := make([]string, 0, len(rec.calls))
		for _, c := range rec.calls {
			calls = append(calls, strings.ReplaceAll(c, base, "<base>"))
		}
		runs = append(runs, calls)
	}
	if !slices.Equal(runs[0], runs[1]) {
		t.Errorf("builds differ:\n%s\n---\n%s", strings.Join(runs[0], "\n"), strings.Join(runs[1], "\n"))
	}
	if manifests[0] != manifests[1] {
		t.Errorf("manifests differ: %+v vs %+v", manifests[0], manifests[1])
	}
	if disklessroot.DeriveSalt(testEpoch, "1.0.0-test") != testSalt || disklessroot.DeriveSalt(testEpoch+1, "1.0.0-test") == testSalt {
		t.Error("the salt is not a function of the epoch and version")
	}
}

func TestGenerateDisklessRootRefusesARootThatWouldNotBoot(t *testing.T) {
	cases := map[string]func(r *disklessRunner){
		"installed root has no /sbin/init": func(r *disklessRunner) { delete(r.tree, "sbin/init") },
		"installed root has no platformd":  func(r *disklessRunner) { delete(r.tree, "usr/bin/platformd") },
		"squashfs has no /sbin/init":       func(r *disklessRunner) { r.listing = strings.ReplaceAll(r.listing, "squashfs-root/sbin/init\n", "") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rec := newDisklessRunner()
			mutate(rec)
			_, err := GenerateDisklessRoot(context.Background(), disklessOptions(t, rec, &fakeAssemble{parts: 2}))
			var content DisklessRootContentError
			if !errors.As(err, &content) {
				t.Fatalf("err = %v, want a DisklessRootContentError", err)
			}
			if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "veritysetup") }) {
				t.Error("a root that would not boot was given a hash tree")
			}
			if !slices.Contains(rec.calls, "losetup --detach "+testLoop) {
				t.Error("the root partition was left attached")
			}
		})
	}
}

func TestGenerateDisklessRootCleansUpOnFailure(t *testing.T) {
	rec := newDisklessRunner()
	rec.fail = "mksquashfs"
	opts := disklessOptions(t, rec, &fakeAssemble{parts: 2})
	_, err := GenerateDisklessRoot(context.Background(), opts)
	var stage *StageError
	if !errors.As(err, &stage) || stage.Step != "mksquashfs" {
		t.Fatalf("err = %v, want the mksquashfs step", err)
	}
	want := expectedDisklessCalls(opts)[:5]
	if !slices.Equal(rec.calls, want) {
		t.Errorf("calls = %q, want %q", rec.calls, want)
	}
}

func TestGenerateDisklessRootFailures(t *testing.T) {
	cases := map[string]struct {
		mutate func(o *DisklessRootOptions, r *disklessRunner, a *fakeAssemble)
		step   string
	}{
		"no config":          {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) { o.Config = nil }, step: "diskless root"},
		"no work dir":        {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) { o.WorkDir = "" }, step: "diskless root"},
		"no output dir":      {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) { o.OutputDir = "" }, step: "diskless root"},
		"negative epoch":     {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) { o.SourceDateEpoch = -1 }, step: "diskless root"},
		"bad salt":           {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) { o.Salt = "XYZ" }, step: "diskless root"},
		"install fails":      {mutate: func(_ *DisklessRootOptions, _ *disklessRunner, a *fakeAssemble) { a.err = errors.New("no space") }, step: "installing the diskless root"},
		"no root partition":  {mutate: func(_ *DisklessRootOptions, _ *disklessRunner, a *fakeAssemble) { a.parts = 1 }, step: "reading the scratch image's partition table"},
		"no partition table": {mutate: func(_ *DisklessRootOptions, _ *disklessRunner, a *fakeAssemble) { a.parts = 0 }, step: "reading the scratch image's partition table"},
		"no loop device": {mutate: func(o *DisklessRootOptions, _ *disklessRunner, _ *fakeAssemble) {
			o.allocateLoop = func() (string, error) { return "", errors.New("busy") }
		}, step: "allocating a loop device"},
		"losetup fails":      {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.fail = "losetup" }, step: "attaching the root partition"},
		"mount fails":        {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.fail = "mount" }, step: "mounting the root partition"},
		"umount fails":       {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.fail = "umount" }, step: "unmounting the root partition"},
		"unsquashfs fails":   {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.fail = "unsquashfs" }, step: "listing the squashfs"},
		"squashfs unaligned": {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.squashSize = 100 }, step: "reading the squashfs"},
		"veritysetup fails":  {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.fail = "veritysetup" }, step: "veritysetup format"},
		"no root hash":       {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) { r.verityOutput = "UUID: x\n" }, step: "reading the verity root hash"},
		"uppercase root hash": {mutate: func(_ *DisklessRootOptions, r *disklessRunner, _ *fakeAssemble) {
			r.verityOutput = "Root hash: " + strings.ToUpper(testVerityRootHash)
		}, step: "reading the verity root hash"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec, asm := newDisklessRunner(), &fakeAssemble{parts: 2}
			opts := disklessOptions(t, rec, asm)
			tc.mutate(&opts, rec, asm)
			_, err := GenerateDisklessRoot(context.Background(), opts)
			var stage *StageError
			if !errors.As(err, &stage) || stage.Step != tc.step {
				t.Fatalf("err = %v, want step %q", err, tc.step)
			}
		})
	}
}

func TestDisklessRootErrorMessages(t *testing.T) {
	cases := map[string]error{
		"diskless root: missing version":                                DisklessRootInputError{Field: "version"},
		"diskless root: size: too big":                                  DisklessRootInputError{Field: "size", Reason: "too big"},
		"diskless root: veritysetup output did not include a root hash": DisklessRootHashError{},
		"diskless root: the squashfs has no /sbin/init":                 DisklessRootContentError{Where: "the squashfs", Path: "sbin/init"},
	}
	for want, err := range cases {
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	}
	inner := errors.New("bad hex")
	if err := (DisklessRootHashError{Output: "zz", Err: inner}); !errors.Is(err, inner) || !strings.Contains(err.Error(), `"zz"`) {
		t.Errorf("hash error = %v", err)
	}
}

// testDBKey is a Secure Boot DB key and its self-signed certificate.
func testDBKey(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test DB"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestBuildDisklessRootSignsTheManifest(t *testing.T) {
	rec := &diskimagetest.Runner{}
	staged, err := StageMedia(context.Background(), buildConfigForTest(t, "qemu-virt", rec))
	if err != nil {
		t.Fatal(err)
	}
	key, cert := testDBKey(t)
	staged.SecureBoot = &iso.SecureBootMaterial{DBKey: key, DBCert: cert}
	out, manifestDir := t.TempDir(), filepath.Join(t.TempDir(), disklessroot.Dir)
	res, err := staged.BuildDisklessRoot(context.Background(), out, manifestDir, testEpoch, "1.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	if res.RootFS != filepath.Join(out, disklessroot.RootFSFile) || res.Verity != filepath.Join(out, disklessroot.VerityFile) {
		t.Errorf("result = %+v", res)
	}
	signed, err := disklessroot.ReadSigned(manifestDir, cert)
	if err != nil {
		t.Fatalf("the manifest does not verify against the DB certificate: %v", err)
	}
	if *signed != res.Manifest || signed.Salt != testSalt || signed.RootHash != testVerityRootHash {
		t.Errorf("signed manifest = %+v, result %+v", signed, res.Manifest)
	}
	if _, err := os.Stat(filepath.Join(out, DisklessRootHashFile)); !os.IsNotExist(err) {
		t.Errorf("the root hash hand-off is served beside the artifacts: %v", err)
	}

	// The step runs the target's platformctl-static, so it builds and runs
	// the target-platform tag, never the host's (#802).
	image := DefaultBuilderImage + ":arm64"
	calls := rec.Joined()
	create, build := "", ""
	for _, c := range calls {
		if strings.Contains(c, "diskless-root") {
			create = c
		}
		if strings.Contains(c, "build --platform linux/arm64") {
			build = c
		}
	}
	if !strings.Contains(build, "-t "+image+" ") {
		t.Errorf("build %q does not tag %q", build, image)
	}
	for _, want := range []string{
		"create --name builder-", "--privileged", "--platform linux/arm64", "-v /work", "-v /out",
		" " + image + " ",
		"/media/cdrom/platformd-bin/platformctl-static diskimage diskless-root",
		"--platform-config /media/cdrom/configs/" + bakedPlatformConfigName,
		"--size 2048", "--work-dir /work", "--output /out",
		"--source-date-epoch 1700000000", "--salt " + testSalt,
	} {
		if !strings.Contains(create, want) {
			t.Errorf("create %q lacks %q", create, want)
		}
	}
	assertNoHostBindMounts(t, rec)
}

func TestBuildDisklessRootFailures(t *testing.T) {
	rec := &diskimagetest.Runner{}
	staged, err := StageMedia(context.Background(), buildConfigForTest(t, "qemu-virt", rec))
	if err != nil {
		t.Fatal(err)
	}
	key, cert := testDBKey(t)
	signing := &iso.SecureBootMaterial{DBKey: key, DBCert: cert}
	cases := map[string]struct {
		media   *StagedMedia
		fail    string
		epoch   int64
		version string
		step    string
	}{
		"no staged media":   {media: &StagedMedia{}, version: "1", step: "diskless root"},
		"no secure boot":    {media: staged, version: "1", step: "diskless root"},
		"no version":        {media: staged, step: "diskless root"},
		"negative epoch":    {media: staged, epoch: -1, version: "1", step: "diskless root"},
		"image build fails": {media: staged, fail: "build", version: "1", step: "building the builder container image"},
		"container fails":   {media: staged, fail: "start", version: "1", step: "running the diskless root step"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if name != "no secure boot" {
				tc.media.SecureBoot = signing
			} else {
				tc.media.SecureBoot = nil
			}
			rec.Fail = tc.fail
			_, err := tc.media.BuildDisklessRoot(context.Background(), t.TempDir(), t.TempDir(), tc.epoch, tc.version)
			var stage *StageError
			if !errors.As(err, &stage) || stage.Step != tc.step {
				t.Fatalf("err = %v, want step %q", err, tc.step)
			}
		})
	}
}

func TestBuildDisklessRootRefusesDebugMedia(t *testing.T) {
	rec := &diskimagetest.Runner{}
	staged, err := StageMedia(context.Background(), buildConfigForTest(t, "qemu-virt", rec))
	if err != nil {
		t.Fatal(err)
	}
	key, cert := testDBKey(t)
	staged.SecureBoot = &iso.SecureBootMaterial{DBKey: key, DBCert: cert}
	staged.config.ISO.Debug = true
	before := len(rec.Joined())

	_, err = staged.BuildDisklessRoot(context.Background(), t.TempDir(), t.TempDir(), testEpoch, "1.0.0-test")
	var in DisklessRootInputError
	if !errors.As(err, &in) || in.Field != "debug" {
		t.Fatalf("err = %v, want a debug DisklessRootInputError", err)
	}
	for _, c := range rec.Joined()[before:] {
		if strings.Contains(c, "diskless-root") || strings.Contains(c, " build ") {
			t.Errorf("a debug root was built: %q", c)
		}
	}
}
