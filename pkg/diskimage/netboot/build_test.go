package netboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso/isotest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

// pinFakeNetboot writes an aarch64 netboot tarball carrying flavour's kernel
// (a PE, so it can be signed), initramfs and modloop into cacheDir, and pins
// it for the test.
func pinFakeNetboot(t *testing.T, cacheDir, flavour string) {
	t.Helper()
	pinFakeRelease(t, cacheDir, "aarch64", flavour)
}

// pinFakeRelease is pinFakeNetboot for any Alpine architecture; earlier pins
// made in the same test are kept.
func pinFakeRelease(t *testing.T, cacheDir, arch, flavour string) {
	t.Helper()
	initramfs, err := isotest.NetbootInitramfs()
	require.NoError(t, err)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string][]byte{
		"boot/vmlinuz-" + flavour:   authenticodetest.MinimalPE(authenticodetest.MachineARM64),
		"boot/initramfs-" + flavour: initramfs,
		"boot/modloop-" + flavour:   []byte("modloop"),
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	file := "alpine-netboot-test-" + arch + ".tar.gz"
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, file), buf.Bytes(), 0o644))
	sum := sha256.Sum256(buf.Bytes())
	saved := alpineNetboots
	pins := map[string]alpineNetboot{}
	for a, p := range saved["3.22.2"] {
		pins[a] = p
	}
	pins[arch] = alpineNetboot{file: file, sha256: hex.EncodeToString(sum[:])}
	alpineNetboots = map[string]map[string]alpineNetboot{"3.22.2": pins}
	t.Cleanup(func() { alpineNetboots = saved })
}

func buildConfig(t *testing.T, platformConfig string) *Config {
	t.Helper()
	isoBuild := iso.DefaultISOBuildConfig()
	isoBuild.PlatformVersion = "1.0.0-test"
	isoBuild.PlatformConfigFile = platformConfig
	isoBuild.PreFetch = false
	isoBuild.SecureBoot = false
	isoBuild.KeysDir = t.TempDir()
	out := filepath.Join(t.TempDir(), "netboot-media")
	return &Config{
		Build: &diskimage.BuildConfig{
			ISO: isoBuild, UBootDir: diskimagetest.UBootOutput(t), VirtKernelDir: diskimagetest.VirtKernelOutput(t),
			Runner: (&diskimagetest.Runner{}).Run, Logger: logging.DefaultLogger(), SkipPreflight: true,
		},
		ARM64BinariesDir: diskimagetest.Binaries(t, elf.EM_AARCH64),
		CacheDir:         filepath.Join(t.TempDir(), "cache"),
		OutputDir:        out,
		Sets:             []Set{ARM64VirtSet},
	}
}

// verifySums re-hashes every file SHA256SUMS lists, as the deployer's
// `sha256sum -c` does.
func verifySums(t *testing.T, root string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, container.NetbootMediaSums))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.NotEmpty(t, lines)
	for _, line := range lines {
		sum, rel, ok := strings.Cut(line, "  ")
		require.True(t, ok, line)
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		require.NoError(t, err, rel)
		want := sha256.Sum256(got)
		assert.Equal(t, hex.EncodeToString(want[:]), sum, rel)
	}
}

// assertInstallerInitramfs checks that the set serves the installer's
// initramfs, not the release's live one: the autoinstall overlay and the
// patched /init that runs it on alpine_start=autoinstall.
func assertInstallerInitramfs(t *testing.T, path string) {
	t.Helper()
	files := isotest.ReadInitramfs(t, path)
	for _, rel := range []string{"overlay/etc/inittab", "overlay/root/autoinstall.sh", "overlay/root/run-autoinstall.sh"} {
		assert.Contains(t, files, rel)
	}
	assert.Contains(t, files["overlay/root/autoinstall.sh"], "fetch_install_payload", "the autoinstall rebuilds its CD from the set")
	assert.Contains(t, files["init"], "if grep -q alpine_start=autoinstall /proc/cmdline")
	assert.Contains(t, files["init"], "trusted-platform: multi-NIC DHCP")
}

// TestBuild_Set builds the virt set: the QEMU stand-in's platform-built
// kernel, with its generated initramfs and modloop.
func TestBuild_Set(t *testing.T) {
	cfg := buildConfig(t, diskimagetest.PlatformConfig(t))

	res, err := Build(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, []string{container.MediaSetARM64Virt}, res.Sets)

	set := filepath.Join(res.Dir, container.NetbootMediaSetsDir, container.MediaSetARM64Virt)
	for _, rel := range []string{"vmlinuz-virt", "initramfs-virt", "modloop-virt", container.PayloadListName, container.MediaSetDescriptor, "cdrom/" + container.InstallerEntryPoint} {
		assert.FileExists(t, filepath.Join(set, filepath.FromSlash(rel)))
	}
	assert.NoDirExists(t, filepath.Join(res.Dir, ".work"), "the work directory is removed")
	assertInstallerInitramfs(t, filepath.Join(set, "initramfs-virt"))
	verifySums(t, res.Dir)
	sets, err := container.LoadMediaSets(filepath.Join(res.Dir, container.NetbootMediaSetsDir), "/data/media")
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, ARM64VirtSet.KernelArgs, sets[0].KernelArgs)
	assert.True(t, sets[0].Default)
}

func TestBuild_SignsTheKernelWithTheKMSKey(t *testing.T) {
	dbKey, db := secureboottest.KeyPair(t, "DB")
	_, pk := secureboottest.KeyPair(t, "PK")
	_, kek := secureboottest.KeyPair(t, "KEK")
	config := filepath.Join(t.TempDir(), "platform.yaml")
	require.NoError(t, os.WriteFile(config, []byte(`os:
  hostname: node
seal-pcrs: [0, 7, 9]
secure-boot:
  enabled: true
  resign-mode: remote
  pk: {key-uri: "kms://sb/pk"}
  kek: {key-uri: "kms://sb/kek"}
  db: {key-uri: "kms://sb/db"}
`), 0o644))
	cfg := buildConfig(t, config)
	cfg.Build.ISO.SecureBoot = true
	cfg.Build.ISO.GenerateKeys = false
	cfg.Build.KMSClients = func() (*iso.KMSClients, error) {
		return &iso.KMSClients{KMS: &secureboottest.KMS{Key: dbKey}, CA: &secureboottest.CA{Certs: map[string]*x509.Certificate{"sb/pk": pk, "sb/kek": kek, "sb/db": db}}}, nil
	}

	res, err := Build(context.Background(), cfg)
	require.NoError(t, err)

	kernel := filepath.Join(res.Dir, container.NetbootMediaSetsDir, container.MediaSetARM64Virt, "vmlinuz-virt")
	verifier := authenticode.NewVerifier(context.Background(), nil)
	require.NoError(t, verifier.VerifyFile(kernel))
	signer, err := verifier.ExtractCertificateFile(kernel)
	require.NoError(t, err)
	assert.True(t, signer.Equal(db), "the kernel is signed by the KMS DB key")
}

func TestBuild_RefusesToServeASigningKey(t *testing.T) {
	config := filepath.Join(t.TempDir(), "platform.yaml")
	require.NoError(t, os.WriteFile(config, []byte("os:\n  hostname: node\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: true\n"), 0o644))
	cfg := buildConfig(t, config)
	cfg.Build.ISO.SecureBoot = true
	cfg.Build.ISO.GenerateKeys = false
	authenticodetest.WriteKeyPair(t, cfg.Build.ISO.KeysDir)
	for _, role := range []string{"PK", "KEK"} {
		_, cert := secureboottest.KeyPair(t, role)
		require.NoError(t, os.WriteFile(filepath.Join(cfg.Build.ISO.KeysDir, role+".crt"), secureboottest.PEM(cert), 0o644))
	}

	_, err := Build(context.Background(), cfg)
	require.Error(t, err, "a set cannot sign with media-staged keys: it would serve DB.key")
	assert.Contains(t, err.Error(), "network-served medium cannot sign with media-staged Secure Boot keys")
}

func TestBuild_ConfigurationErrors(t *testing.T) {
	var buildErr *BuildError
	for name, cfg := range map[string]*Config{
		"nil":               nil,
		"no image build":    {OutputDir: t.TempDir()},
		"no output":         {Build: &diskimage.BuildConfig{ISO: iso.DefaultISOBuildConfig()}},
		"no arm64 binaries": {Build: &diskimage.BuildConfig{ISO: iso.DefaultISOBuildConfig()}, OutputDir: t.TempDir(), Sets: []Set{ARM64VirtSet}},
		"pi without iPXE":   {Build: &diskimage.BuildConfig{ISO: iso.DefaultISOBuildConfig()}, OutputDir: t.TempDir(), ARM64BinariesDir: t.TempDir(), X86BinariesDir: t.TempDir()},
		"no x86 binaries":   {Build: &diskimage.BuildConfig{ISO: iso.DefaultISOBuildConfig()}, OutputDir: t.TempDir(), Sets: []Set{X86_64Set}},
		"arm64 set without a target": {Build: &diskimage.BuildConfig{ISO: iso.DefaultISOBuildConfig()}, OutputDir: t.TempDir(), ARM64BinariesDir: t.TempDir(),
			Sets: []Set{{Name: "a", Architecture: ipxe.ArchitectureARM64, Flavour: "virt"}}},
	} {
		_, err := Build(context.Background(), cfg)
		assert.ErrorAs(t, err, &buildErr, name)
	}
}

func TestPiBootFiles(t *testing.T) {
	prefetch := t.TempDir()
	writeAPK(t, prefetch, "raspberrypi-bootloader", "1.20250101-r0", map[string]string{"boot/start4.elf": "ELF4", "boot/fixup4.dat": "FIX4"})
	writeAPK(t, prefetch, "raspberrypi-bootloader-common", "1.20250101-r0", map[string]string{"boot/bootcode.bin": "BOOT"})
	writeAPK(t, prefetch, "linux-rpi", "6.12.0-r0", map[string]string{"boot/bcm2711-rpi-4-b.dtb": "dtb4", "boot/overlays/disable-bt.dtbo": "bt"})
	media := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(media, "apks-prefetch"), 0o755))
	require.NoError(t, os.Rename(prefetch, filepath.Join(media, "apks-prefetch", "aarch64")))
	ubootDir := filepath.Join(diskimagetest.UBootOutput(t), string(uboot.BoardRPiArm64))
	art := uboot.Artifacts{Board: uboot.BoardRPiArm64, Dir: ubootDir, Binary: filepath.Join(ubootDir, "u-boot.bin"), OverlaysDir: filepath.Join(ubootDir, "overlays")}
	target, err := diskimage.NewTarget("rpi", "rpi4")
	require.NoError(t, err)

	pe := authenticodetest.MinimalPE(authenticodetest.MachineARM64)
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	db, err := authenticode.NewFileSigner(context.Background(), keyPath, certPath, nil)
	require.NoError(t, err)
	cfg := &Config{OutputDir: t.TempDir(), Model: "rpi4", IPXEFile: writeIPXE(t, pe)}
	material := &iso.SecureBootMaterial{DB: db}
	image := &diskimage.StagedMedia{Target: target, MediaDir: media, UBoot: art, SecureBoot: material}
	set := &stagedSet{media: &setMedia{dir: media, secureBoot: material, image: image}}

	require.NoError(t, cfg.piBootFiles(context.Background(), set))
	assert.FileExists(t, filepath.Join(cfg.OutputDir, TFTPTreeDir, "kernel8.img"))
	assert.FileExists(t, filepath.Join(cfg.OutputDir, TFTPTreeDir, "config.txt"))
	signed := filepath.Join(cfg.OutputDir, filepath.FromSlash(ARM64IPXEFile))
	require.NoError(t, authenticode.NewVerifier(context.Background(), nil).VerifyFile(signed), "the iPXE is db-signed")

	t.Run("without Secure Boot the iPXE is placed as built", func(t *testing.T) {
		plain := &Config{OutputDir: t.TempDir(), Model: "rpi4", IPXEFile: cfg.IPXEFile}
		unsigned := &stagedSet{media: &setMedia{dir: media, image: image}}
		require.NoError(t, plain.piBootFiles(context.Background(), unsigned))
		got, err := os.ReadFile(filepath.Join(plain.OutputDir, filepath.FromSlash(ARM64IPXEFile)))
		require.NoError(t, err)
		assert.Equal(t, pe, got)
	})
	t.Run("a set without the Pi firmware packages", func(t *testing.T) {
		empty := t.TempDir()
		bare := &stagedSet{media: &setMedia{dir: empty, image: &diskimage.StagedMedia{Target: target, MediaDir: empty, UBoot: art}}}
		var buildErr *BuildError
		require.ErrorAs(t, cfg.piBootFiles(context.Background(), bare), &buildErr)
		assert.Equal(t, "staging the TFTP tree", buildErr.Step)
	})
	t.Run("an iPXE that is not a PE image cannot be db-signed", func(t *testing.T) {
		notPE := &Config{OutputDir: t.TempDir(), Model: "rpi4", IPXEFile: writeIPXE(t, []byte("not a PE image"))}
		var buildErr *BuildError
		require.ErrorAs(t, notPE.piBootFiles(context.Background(), set), &buildErr)
		assert.Equal(t, "signing the arm64 iPXE", buildErr.Step)
		assert.NoFileExists(t, filepath.Join(notPE.OutputDir, filepath.FromSlash(ARM64IPXEFile)))
	})
	t.Run("a tampered iPXE is refused", func(t *testing.T) {
		require.NoError(t, os.WriteFile(cfg.IPXEFile, []byte("tampered"), 0o644))
		var buildErr *BuildError
		require.ErrorAs(t, cfg.piBootFiles(context.Background(), set), &buildErr)
	})
}

// writeIPXE writes an arm64 iPXE build of data with the SHA256SUMS `make
// ipxe-build` leaves beside it, and returns its path.
func writeIPXE(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snponly.efi"), data, 0o644))
	sum := sha256.Sum256(data)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hex.EncodeToString(sum[:])+"  ./snponly.efi\n"), 0o644))
	return filepath.Join(dir, "snponly.efi")
}

func TestRefusePrivateKeys(t *testing.T) {
	cdrom := t.TempDir()
	require.NoError(t, refusePrivateKeys(cdrom), "no secure-boot-keys directory")

	keys := filepath.Join(cdrom, iso.SecureBootKeysISODirName)
	require.NoError(t, os.MkdirAll(keys, 0o755))
	_, cert := secureboottest.KeyPair(t, "DB")
	require.NoError(t, os.WriteFile(filepath.Join(keys, "DB.crt"), secureboottest.PEM(cert), 0o644))
	require.NoError(t, refusePrivateKeys(cdrom), "a certificate is public")

	require.NoError(t, os.WriteFile(filepath.Join(keys, "DB.key"), []byte("-----BEGIN PRIVATE KEY-----"), 0o600))
	var private *PrivateKeyMaterialError
	require.ErrorAs(t, refusePrivateKeys(cdrom), &private)
	assert.Contains(t, private.Error(), "DB.key")
}

// Key material that cannot be read is never passed as public.
func TestRefusePrivateKeys_UnreadableKeyMaterial(t *testing.T) {
	t.Run("secure-boot-keys is a file", func(t *testing.T) {
		cdrom := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(cdrom, iso.SecureBootKeysISODirName), []byte("-----BEGIN PRIVATE KEY-----"), 0o600))
		assert.Error(t, refusePrivateKeys(cdrom))
	})
	t.Run("a directory under secure-boot-keys", func(t *testing.T) {
		cdrom := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(cdrom, iso.SecureBootKeysISODirName, "private"), 0o755))
		assert.Error(t, refusePrivateKeys(cdrom))
	})
}

func TestFetchAlpineNetboot_Unpinned(t *testing.T) {
	var unpinned *UnpinnedReleaseError
	_, err := fetchAlpineNetboot(context.Background(), "9.9.9", "aarch64", "http://127.0.0.1:1", t.TempDir())
	require.ErrorAs(t, err, &unpinned)
	assert.Contains(t, unpinned.Error(), "9.9.9")
}

func TestExtractFlavour_MissingFile(t *testing.T) {
	cache := t.TempDir()
	pinFakeNetboot(t, cache, "virt")
	tarball, err := fetchAlpineNetboot(context.Background(), "3.22.2", "aarch64", "http://127.0.0.1:1", cache)
	require.NoError(t, err, "a cached tarball with the pinned digest needs no download")

	_, err = extractFlavour(tarball, "rpi", t.TempDir())
	var missing *MissingFileError
	require.True(t, errors.As(err, &missing), "the tarball has no rpi flavour: %v", err)
}

func TestExtractFlavour_MalformedTarball(t *testing.T) {
	tarball := filepath.Join(t.TempDir(), "alpine-netboot.tar.gz")
	require.NoError(t, os.WriteFile(tarball, []byte("not a gzip stream"), 0o644))
	_, err := extractFlavour(tarball, "rpi", t.TempDir())
	var netbootErr *Error
	require.ErrorAs(t, err, &netbootErr)
	assert.Equal(t, tarball, netbootErr.Source)
	var missing *MissingFileError
	assert.False(t, errors.As(err, &missing), "a corrupt tarball is not reported as a missing flavour")
}

// A cached tarball that no longer matches its pinned digest is never used: the
// build goes back to the mirror, and fails when the mirror cannot serve it.
func TestFetchAlpineNetboot_TamperedCache(t *testing.T) {
	cache := t.TempDir()
	pinFakeNetboot(t, cache, "virt")
	pinned := alpineNetboots["3.22.2"]["aarch64"]
	require.NoError(t, os.WriteFile(filepath.Join(cache, pinned.file), []byte("tampered"), 0o644))

	_, err := fetchAlpineNetboot(context.Background(), "3.22.2", "aarch64", "http://127.0.0.1:1", cache)
	var netbootErr *Error
	require.ErrorAs(t, err, &netbootErr)
	assert.Equal(t, pinned.file, netbootErr.Source)
}

// TestBootFiles_PackagedKernel: a target on a packaged kernel boots Alpine's
// netboot flavour, from the digest-pinned release.
func TestBootFiles_PackagedKernel(t *testing.T) {
	cfg := &Config{CacheDir: t.TempDir()}
	pinFakeNetboot(t, cfg.CacheDir, "rpi")
	target, err := diskimage.NewTarget("rpi", "rpi4")
	require.NoError(t, err)
	isoBuild := iso.DefaultISOBuildConfig()
	dir := t.TempDir()

	files, err := cfg.bootFiles(context.Background(), RaspberryPiSet, &setMedia{arch: "aarch64", image: &diskimage.StagedMedia{Target: target}}, isoBuild, dir)
	require.NoError(t, err)
	assert.Equal(t, flavourFiles{Kernel: "vmlinuz-rpi", Initrd: "initramfs-rpi", Modloop: "modloop-rpi"}, files)
	for _, name := range []string{files.Kernel, files.Initrd, files.Modloop} {
		assert.FileExists(t, filepath.Join(dir, name))
	}

	isoBuild.AlpineVersion = "9.9.9"
	var unpinned *UnpinnedReleaseError
	_, err = cfg.bootFiles(context.Background(), RaspberryPiSet, &setMedia{arch: "aarch64", image: &diskimage.StagedMedia{Target: target}}, isoBuild, t.TempDir())
	require.ErrorAs(t, err, &unpinned)
}

// TestBuild_X86Set builds the x86_64 installer: the installer media alone,
// no diskimage target, Alpine's lts netboot flavour.
func TestBuild_X86Set(t *testing.T) {
	cfg := buildConfig(t, diskimagetest.PlatformConfig(t))
	cfg.X86BinariesDir = diskimagetest.Binaries(t, elf.EM_X86_64)
	cfg.Sets = []Set{X86_64Set}
	pinFakeRelease(t, cfg.CacheDir, "x86_64", "lts")

	res, err := Build(context.Background(), cfg)
	require.NoError(t, err)
	set := filepath.Join(res.Dir, container.NetbootMediaSetsDir, container.MediaSetX86_64)
	for _, rel := range []string{"vmlinuz-lts", "initramfs-lts", "modloop-lts", "cdrom/" + container.InstallerEntryPoint} {
		assert.FileExists(t, filepath.Join(set, filepath.FromSlash(rel)))
	}
	assert.NoDirExists(t, filepath.Join(set, "cdrom", "boot-firmware"), "no target firmware: the machine's own UEFI boots it")
	assertInstallerInitramfs(t, filepath.Join(set, "initramfs-lts"))
	sets, err := container.LoadMediaSets(filepath.Join(res.Dir, container.NetbootMediaSetsDir), "/data/media")
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, ipxe.ArchitectureX86_64, sets[0].Architecture)
	assert.Equal(t, X86_64Set.KernelArgs, sets[0].KernelArgs)
	verifySums(t, res.Dir)
}

// A failed build names the set and the step that stopped it.
func TestBuild_FailsNamingTheSetAndStep(t *testing.T) {
	x86 := func(t *testing.T) *Config {
		cfg := buildConfig(t, diskimagetest.PlatformConfig(t))
		cfg.X86BinariesDir = diskimagetest.Binaries(t, elf.EM_X86_64)
		cfg.Sets = []Set{X86_64Set}
		return cfg
	}

	t.Run("the release has no such flavour", func(t *testing.T) {
		cfg := x86(t)
		cfg.Build.Logger = nil
		pinFakeRelease(t, cfg.CacheDir, "x86_64", "virt")
		_, err := Build(context.Background(), cfg)
		var buildErr *BuildError
		require.ErrorAs(t, err, &buildErr)
		assert.Equal(t, container.MediaSetX86_64, buildErr.Set)
		assert.Contains(t, buildErr.Step, X86_64Set.Flavour)
		var missing *MissingFileError
		assert.ErrorAs(t, err, &missing)
	})
	t.Run("the set's binaries lack platformd", func(t *testing.T) {
		cfg := x86(t)
		cfg.X86BinariesDir = t.TempDir()
		_, err := Build(context.Background(), cfg)
		var buildErr *BuildError
		require.ErrorAs(t, err, &buildErr)
		assert.Equal(t, container.MediaSetX86_64, buildErr.Set)
		assert.Equal(t, "staging the install media", buildErr.Step)
	})
	t.Run("the output directory cannot be cleared", func(t *testing.T) {
		cfg := x86(t)
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o644))
		cfg.OutputDir = filepath.Join(file, "netboot-media")
		_, err := Build(context.Background(), cfg)
		var buildErr *BuildError
		require.ErrorAs(t, err, &buildErr)
		assert.Equal(t, "clearing "+cfg.OutputDir, buildErr.Step)
	})
}

func TestPlaceKernel(t *testing.T) {
	kernel := authenticodetest.MinimalPE(authenticodetest.MachineARM64)
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	db, err := authenticode.NewFileSigner(context.Background(), keyPath, certPath, nil)
	require.NoError(t, err)
	material := &iso.SecureBootMaterial{DB: db}
	released := func(t *testing.T) string {
		src := filepath.Join(t.TempDir(), "vmlinuz-rpi")
		require.NoError(t, os.WriteFile(src, kernel, 0o644))
		return src
	}

	t.Run("without Secure Boot the kernel is placed as released", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "vmlinuz-rpi")
		require.NoError(t, placeKernel(released(t), dst, nil))
		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, kernel, got)
	})
	t.Run("with Secure Boot the kernel is db-signed", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "vmlinuz-rpi")
		require.NoError(t, placeKernel(released(t), dst, material))
		require.NoError(t, authenticode.NewVerifier(context.Background(), nil).VerifyFile(dst))
	})
	t.Run("a missing kernel", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "absent")
		dst := filepath.Join(t.TempDir(), "vmlinuz-rpi")
		assert.Error(t, placeKernel(src, dst, nil))
		assert.Error(t, placeKernel(src, dst, material))
		assert.NoFileExists(t, dst)
	})
}

func TestAlpineArch(t *testing.T) {
	assert.Equal(t, "aarch64", alpineArch(ipxe.ArchitectureARM64))
	assert.Equal(t, "x86_64", alpineArch(ipxe.ArchitectureX86_64))
}

// SHA256SUMS lists every file of the build but itself, relative and
// slash-separated, as the deployer's `sha256sum -c` reads it.
func TestWriteChecksums(t *testing.T) {
	root := t.TempDir()
	set := filepath.Join(root, container.NetbootMediaSetsDir, container.MediaSetRaspberryPi)
	require.NoError(t, os.MkdirAll(set, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(set, "vmlinuz-rpi"), []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, container.NetbootMediaIndex), []byte("index"), 0o644))

	require.NoError(t, writeChecksums(root))
	require.NoError(t, writeChecksums(root), "a rebuild never hashes the previous SHA256SUMS")
	verifySums(t, root)
	data, err := os.ReadFile(filepath.Join(root, container.NetbootMediaSums))
	require.NoError(t, err)
	assert.Contains(t, string(data), "  "+container.NetbootMediaSetsDir+"/"+container.MediaSetRaspberryPi+"/vmlinuz-rpi\n")
	assert.Equal(t, 2, strings.Count(string(data), "\n"))

	var buildErr *BuildError
	require.ErrorAs(t, writeChecksums(filepath.Join(root, "absent")), &buildErr)
	assert.Equal(t, "hashing the build", buildErr.Step)
}
