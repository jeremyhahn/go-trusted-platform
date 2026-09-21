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
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// DefaultESPUKIPath is the UEFI removable-media boot path where the platform
// installer writes the signed UKI. All UEFI firmware discovers this path
// automatically, and the install-time efibootmgr NVRAM entry points at it, so
// an atomic replacement here keeps every existing boot path valid.
const DefaultESPUKIPath = "/boot/efi/EFI/BOOT/BOOTX64.EFI"

// DefaultESPBootDir is the EFI/BOOT directory on the mounted EFI system
// partition of an installed node.
const DefaultESPBootDir = "/boot/efi/EFI/BOOT"

// ESPUKIPathFor returns the live UKI path on the ESP for arch: DefaultESPUKIPath
// for x86_64, /boot/efi/EFI/BOOT/BOOTAA64.EFI for aarch64, and so on.
func ESPUKIPathFor(arch uki.Architecture) (string, error) {
	name, err := uki.BootFileName(arch)
	if err != nil {
		return "", err
	}
	return filepath.Join(DefaultESPBootDir, name), nil
}

// hostESPUKIPath is the live UKI path for the architecture this binary runs
// on. uki.HostArchitecture only yields architectures BootFileName knows (a
// pkg/uki test pins that), so the x86_64 constant is reached only if that
// invariant is broken.
func hostESPUKIPath() string {
	path, err := ESPUKIPathFor(uki.HostArchitecture())
	if err != nil {
		return DefaultESPUKIPath
	}
	return path
}

// DefaultModulesDir is the on-node kernel modules root used to discover the
// newest installed kernel version when one is not supplied explicitly.
const DefaultModulesDir = "/lib/modules"

// DefaultBootDir holds the installed kernel images (vmlinuz-<kver>).
const DefaultBootDir = "/boot"

// DefaultKernelCmdlinePath is where the installer persists the kernel command
// line (buildUKI writes it). The on-node rebuild reads it back so the rebuilt
// UKI carries exactly the cmdline the node booted with.
const DefaultKernelCmdlinePath = "/etc/kernel/cmdline"

// moduleSignatureMagic is the trailer the kernel module signer (scripts/sign-file)
// appends to a signed .ko. Its presence at EOF proves the module carries a
// signature the kernel can verify, which is required under CONFIG_MODULE_SIG_FORCE.
const moduleSignatureMagic = "~Module signature appended~\n"

// moduleSpotCheckSampleSize bounds how many .ko files the post-rebuild module
// signature spot check samples — enough to detect "module signing is off"
// without walking thousands of modules.
const moduleSpotCheckSampleSize = 16

// errStopWalk halts filepath.WalkDir once enough modules have been sampled.
var errStopWalk = errors.New("stop walk")

// RemoteSignerResolver resolves a Secure Boot DB signer plus its public
// certificate from a remote KMS via hash-signing (the private key never leaves
// the server). It is the exported seam the Phase 5a kernel-update CLI wires from
// secureboot.NewRemoteSigner over the platform SDK client; resolveRebuildSigner
// invokes it for resign-mode == remote. It carries the same shape as the
// installer's internal remoteSignerResolver but is exported so the CLI package
// can supply it.
type RemoteSignerResolver func(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error)

// authenticodeSignerFactory builds the Authenticode signer/verifier from a
// resolved DB key + certificate. The production factory mirrors signUKI exactly;
// tests inject a fake to exercise the rebuild pipeline without a real PE file or
// a working dracut.
type authenticodeSignerFactory func(ctx context.Context, signingKey crypto.PrivateKey, cert *x509.Certificate, logger *logging.Logger) (authenticode.Authenticode, error)

// defaultAuthenticodeSigner constructs the native Authenticode signer over the
// resolved DB key, identical to the install-time signUKI path.
func defaultAuthenticodeSigner(ctx context.Context, signingKey crypto.PrivateKey, cert *x509.Certificate, logger *logging.Logger) (authenticode.Authenticode, error) {
	return authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      &secureBootKeyBackend{privateKey: signingKey, logger: logger},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot"},
		Certificate:   cert,
		Logger:        logger,
	})
}

// UKIRebuilder rebuilds and re-signs the Unified Kernel Image on a booted node
// after a kernel package change, then atomically swaps it into the ESP so the
// node stays bootable under CONFIG_MODULE_SIG_FORCE + enforced UEFI Secure Boot.
//
// It is the post-install counterpart of the installer's buildUKI + signUKI
// steps, but runs against the LIVE root (no chroot, no /mnt): it reuses the
// dracut UKI builder, the same DB-signer resolution precedence as
// resolveSecureBootSigner (file:// local or remote KMS hash-signing) and the
// same native Authenticode signer.
//
// Never-brick invariants:
//   - It NEVER generates a fresh DB key. A new, unenrolled key would produce a
//     UKI the firmware refuses, so a missing signer is a hard error, not a
//     fallback to generation.
//   - It builds and signs to a staging file and VERIFIES the signature against
//     the DB certificate (and spot-checks module signatures) BEFORE touching the
//     live UKI.
//   - The swap is a single atomic same-filesystem rename; the previous UKI is
//     preserved as "<uki>.prev". Any failure before the rename leaves the
//     working UKI untouched and returns a non-zero error so the kernel hook logs
//     it and the OLD kernel still boots.
type UKIRebuilder struct {
	logger        *logging.Logger
	config        *Config
	builder       UKIBuilder
	signerFactory authenticodeSignerFactory
	remoteSigner  RemoteSignerResolver
	espUKIPath    string
	modulesDir    string
	bootDir       string
	kernelCmdline string
}

// UKIRebuildOption customises a UKIRebuilder. Production callers typically only
// set WithRemoteSigner (for resign-mode remote) and optionally WithESPUKIPath;
// the path overrides exist so tests can target a temp ESP/modules tree without
// touching the host.
type UKIRebuildOption func(*UKIRebuilder)

// WithUKIBuilder overrides the dracut-based UKI builder (used by tests).
func WithUKIBuilder(b UKIBuilder) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.builder = b }
}

// WithRemoteSigner wires the remote KMS hash-signing seam for resign-mode remote.
func WithRemoteSigner(seam RemoteSignerResolver) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.remoteSigner = seam }
}

// WithAuthenticodeSigner overrides the Authenticode signer factory (used by tests).
func WithAuthenticodeSigner(f authenticodeSignerFactory) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.signerFactory = f }
}

// WithESPUKIPath overrides the live UKI path that is atomically replaced.
func WithESPUKIPath(path string) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.espUKIPath = path }
}

// WithModulesDir overrides the kernel modules root used for kver discovery and
// the module-signature spot check.
func WithModulesDir(path string) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.modulesDir = path }
}

// WithBootDir overrides the directory that holds the kernel images.
func WithBootDir(path string) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.bootDir = path }
}

// WithKernelCmdlinePath overrides the persisted kernel cmdline file.
func WithKernelCmdlinePath(path string) UKIRebuildOption {
	return func(r *UKIRebuilder) { r.kernelCmdline = path }
}

// NewUKIRebuilder constructs a UKIRebuilder with production defaults. The dracut
// UKI builder and native Authenticode signer match the install-time pipeline so
// a rebuilt UKI is byte-compatible with the one the installer produced.
func NewUKIRebuilder(logger *logging.Logger, config *Config, opts ...UKIRebuildOption) *UKIRebuilder {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	r := &UKIRebuilder{
		logger:        logger,
		config:        config,
		builder:       NewDracutUKIBuilder(logger),
		signerFactory: defaultAuthenticodeSigner,
		espUKIPath:    hostESPUKIPath(),
		modulesDir:    DefaultModulesDir,
		bootDir:       DefaultBootDir,
		kernelCmdline: DefaultKernelCmdlinePath,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Rebuild rebuilds, re-signs, verifies, and atomically swaps the UKI for kver.
// When kver is empty it defaults to the newest kernel under the modules dir.
func (r *UKIRebuilder) Rebuild(ctx context.Context, kver string) error {
	if r.config == nil || r.config.SecureBoot == nil || !r.config.SecureBoot.Enabled {
		return ErrSecureBoot("uki-rebuild requires secure-boot.enabled (no DB key to re-sign with)", nil)
	}

	if kver == "" {
		latest, err := latestKernelVersion(r.modulesDir)
		if err != nil {
			return err
		}
		kver = latest
		r.logger.Info("[UKI-REBUILD] Defaulted kernel version to newest installed", "kver", kver)
	}
	r.logger.Info("[UKI-REBUILD] Rebuilding UKI", "kver", kver, "uki", r.espUKIPath)

	kernelPath, err := r.resolveKernelPath(kver)
	if err != nil {
		return err
	}

	cmdline, err := r.readKernelCmdline()
	if err != nil {
		return err
	}

	// Resolve the DB signer FIRST so a signing-material problem aborts before we
	// spend time running dracut. NEVER generates a key.
	signingKey, dbCert, err := resolveRebuildSigner(ctx, r.config.SecureBoot, r.remoteSigner)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "uki-rebuild-*")
	if err != nil {
		return ErrUKIBuild("create temp working directory", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			r.logger.Warn("[UKI-REBUILD] failed to remove temp directory", "error", rmErr)
		}
	}()

	unsignedPath := filepath.Join(tmpDir, "uki.efi")
	if err := r.buildUnsignedUKI(ctx, kernelPath, cmdline, unsignedPath); err != nil {
		return err
	}

	// Sign into a staging file that lives in the ESP directory (same filesystem
	// as the live UKI) so the final swap is a single atomic rename, not a
	// cross-filesystem copy.
	stagingPath := r.espUKIPath + ".new"
	signer, err := r.signerFactory(ctx, signingKey, dbCert, r.logger)
	if err != nil {
		return ErrSecureBoot("create authenticode signer for re-sign", err)
	}
	if err := signer.SignFile(unsignedPath, stagingPath); err != nil {
		r.removeStaging(stagingPath)
		return ErrSecureBoot("sign rebuilt UKI", err)
	}

	// Brick guard: the staged UKI must verify against the DB certificate AND the
	// freshly installed modules must look signed, BEFORE we replace the live UKI.
	if err := r.verifyStaged(signer, stagingPath, dbCert, kver); err != nil {
		r.removeStaging(stagingPath)
		return err
	}

	if err := r.atomicSwap(stagingPath); err != nil {
		r.removeStaging(stagingPath)
		return err
	}

	r.logger.Info("[UKI-REBUILD] UKI rebuilt, re-signed, verified, and atomically swapped",
		"kver", kver, "uki", r.espUKIPath, "previous", r.espUKIPath+".prev")
	return nil
}

// buildUnsignedUKI runs the dracut UKI builder for the resolved kernel + cmdline,
// writing the unsigned UKI to outputPath.
func (r *UKIRebuilder) buildUnsignedUKI(ctx context.Context, kernelPath, cmdline, outputPath string) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return ErrUKIBuild("create unsigned UKI output", err)
	}
	defer func() { _ = out.Close() }()

	ukiConfig := &UKIConfig{
		KernelPath: kernelPath,
		Cmdline:    cmdline,
	}
	if r.config.OS != nil {
		ukiConfig.OSRelease = generateOSRelease(r.config.OS)
	}
	if err := r.builder.BuildUKI(ctx, ukiConfig, out); err != nil {
		return ErrUKIBuild("rebuild UKI with dracut", err)
	}
	if err := out.Sync(); err != nil {
		return ErrUKIBuild("sync unsigned UKI", err)
	}
	return nil
}

// verifyStaged confirms the staged UKI carries a valid Authenticode signature
// whose certificate is exactly dbCert (the verify-before-swap brick guard) and
// spot-checks that the freshly installed kernel modules are signed.
func (r *UKIRebuilder) verifyStaged(verifier authenticode.Authenticode, stagingPath string, dbCert *x509.Certificate, kver string) error {
	if err := uefi.VerifySignedUKI(verifier, stagingPath, dbCert, r.logger); err != nil {
		return &ErrUKIRebuildVerify{Path: stagingPath, Cause: err}
	}
	if err := spotCheckModuleSignatures(filepath.Join(r.modulesDir, kver), r.logger); err != nil {
		return err
	}
	return nil
}

// atomicSwap copies the live UKI to "<uki>.prev" (best effort) and then atomically
// replaces the live UKI with the staged file. The rename is the single committing
// operation: until it runs the live UKI is untouched, and it is atomic on the FAT32
// ESP, so the node can never be left without a bootable UKI.
func (r *UKIRebuilder) atomicSwap(stagingPath string) error {
	if _, err := os.Stat(r.espUKIPath); err == nil {
		prevPath := r.espUKIPath + ".prev"
		if copyErr := copyFile(r.espUKIPath, prevPath); copyErr != nil {
			// .prev is a manual-recovery convenience; the atomic rename below is
			// the real never-brick guarantee, so a failed backup only warns.
			r.logger.Warn("[UKI-REBUILD] failed to preserve previous UKI as .prev", "error", copyErr)
		}
	}

	if err := os.Rename(stagingPath, r.espUKIPath); err != nil {
		return ErrUKIBuild("atomically swap rebuilt UKI into the ESP", err)
	}

	// Flush the replacement to the physical FAT32 ESP before returning so a power
	// loss immediately after the rename cannot lose the new UKI.
	if f, err := os.Open(r.espUKIPath); err == nil {
		if syncErr := f.Sync(); syncErr != nil {
			r.logger.Warn("[UKI-REBUILD] fsync on swapped UKI failed", "error", syncErr)
		}
		_ = f.Close()
	}
	if d, err := os.Open(filepath.Dir(r.espUKIPath)); err == nil {
		if syncErr := d.Sync(); syncErr != nil {
			r.logger.Warn("[UKI-REBUILD] fsync on ESP directory failed", "error", syncErr)
		}
		_ = d.Close()
	}
	return nil
}

// removeStaging discards the staging file after an aborted rebuild so a stale
// "<uki>.new" never lingers next to the live UKI.
func (r *UKIRebuilder) removeStaging(stagingPath string) {
	if err := os.Remove(stagingPath); err != nil && !os.IsNotExist(err) {
		r.logger.Warn("[UKI-REBUILD] failed to remove staging UKI", "path", stagingPath, "error", err)
	}
}

// resolveKernelPath locates the kernel image for kver under bootDir, preferring
// the FIPS kernel when FIPS mode is enabled and falling back to the generic
// vmlinuz-lts, mirroring buildUKI's selection.
func (r *UKIRebuilder) resolveKernelPath(kver string) (string, error) {
	var candidates []string
	if r.config.OS != nil && r.config.OS.FIPS {
		candidates = append(candidates, filepath.Join(r.bootDir, "vmlinuz-fips"))
	}
	candidates = append(candidates,
		filepath.Join(r.bootDir, "vmlinuz-"+kver),
		filepath.Join(r.bootDir, "vmlinuz-lts"),
	)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", &ErrKernelImageNotFound{Kver: kver, BootDir: r.bootDir}
}

// readKernelCmdline reads the persisted kernel command line. A missing or empty
// cmdline is a hard error: rebuilding a UKI without the node's root=/rd.luks.*
// parameters would yield an unbootable image, so we abort rather than guess.
func (r *UKIRebuilder) readKernelCmdline() (string, error) {
	data, err := os.ReadFile(r.kernelCmdline)
	if err != nil {
		return "", &ErrKernelCmdlineUnavailable{Path: r.kernelCmdline, Cause: err}
	}
	cmdline := strings.TrimSpace(string(data))
	if cmdline == "" {
		return "", &ErrKernelCmdlineUnavailable{Path: r.kernelCmdline, Cause: errors.New("file is empty")}
	}
	return cmdline, nil
}

// resolveRebuildSigner resolves the Secure Boot DB signer + certificate used to
// re-sign the UKI, with the SAME precedence as the installer's
// resolveSecureBootSigner EXCEPT it never generates a key:
//
//	(a) file:// DB KeyURI -> read the PEM keypair from the encrypted root.
//	(b) resign-mode remote + a wired seam -> remote KMS hash-signing.
//
// Generating a fresh DB key on a kernel update would brick Secure Boot (the new
// key is not enrolled), so when neither branch resolves this returns a typed
// error and the caller aborts the swap, leaving the working UKI in place.
func resolveRebuildSigner(ctx context.Context, sb *SecureBootConfig, remote RemoteSignerResolver) (crypto.PrivateKey, *x509.Certificate, error) {
	if sb == nil || !sb.Enabled {
		return nil, nil, ErrSecureBoot("secure boot is not enabled; nothing to re-sign", nil)
	}

	// (a) Explicit file:// DB key on the encrypted root (resign-mode local).
	if fileURIPath(sb.DB.KeyURI) != "" {
		key, cert, err := loadFileURISecureBootSigner(sb)
		if err != nil {
			return nil, nil, err
		}
		if key != nil {
			return key, cert, nil
		}
	}

	// (b) Remote KMS hash-signing (resign-mode remote): the private key stays in
	// the CP-KMS, only the digest is round-tripped over the platform SDK seam.
	if sb.ResignMode == SecureBootResignModeRemote && remote != nil {
		attrs, err := sb.DB.ToKeyAttributes()
		if err != nil {
			return nil, nil, ErrSecureBoot("derive DB key attributes for remote re-sign", err)
		}
		signer, cert, err := remote(ctx, attrs)
		if err != nil {
			return nil, nil, ErrSecureBoot("resolve remote DB signer for re-sign", err)
		}
		if signer == nil {
			return nil, nil, ErrSecureBoot("remote DB signer resolved to nil", nil)
		}
		return signer, cert, nil
	}

	return nil, nil, ErrSecureBoot(
		"no Secure Boot DB signer available for kernel-update re-sign "+
			"(configure a file:// DB key on the encrypted root, or resign-mode remote with a reachable KMS)", nil)
}

// loadFileURISecureBootSigner reads the DB keypair referenced by a file:// DB
// KeyURI plus its companion certificate (the file:// CertURI, or the sibling
// DB.crt next to the key when CertURI is empty). It is the shared body behind
// installer.loadFileURISecureBootKeys and the kernel-update re-sign path.
func loadFileURISecureBootSigner(sb *SecureBootConfig) (crypto.PrivateKey, *x509.Certificate, error) {
	if sb == nil {
		return nil, nil, nil
	}
	keyPath := fileURIPath(sb.DB.KeyURI)
	if keyPath == "" {
		return nil, nil, nil
	}
	certPath := fileURIPath(sb.DB.CertURI)
	if certPath == "" {
		// The public cert conventionally lives beside the key as DB.crt.
		certPath = filepath.Join(filepath.Dir(keyPath), "DB.crt")
	}

	key, err := parsePEMPrivateKey(keyPath)
	if err != nil {
		return nil, nil, ErrSecureBoot("read file:// secure boot DB key", err)
	}
	cert, err := parsePEMCertificate(certPath)
	if err != nil {
		return nil, nil, ErrSecureBoot("read file:// secure boot DB cert", err)
	}
	return key, cert, nil
}

// latestKernelVersion returns the newest kernel version directory under
// modulesDir, comparing dotted-numeric components so 6.6.67 sorts after 6.6.9.
func latestKernelVersion(modulesDir string) (string, error) {
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return "", &ErrNoKernelModules{ModulesDir: modulesDir, Cause: err}
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return "", &ErrNoKernelModules{ModulesDir: modulesDir}
	}
	sort.SliceStable(versions, func(i, j int) bool {
		return kernelVersionLess(versions[i], versions[j])
	})
	return versions[len(versions)-1], nil
}

// kernelVersionLess reports whether kernel version a is older than b, comparing
// numeric components in order and breaking ties lexicographically.
func kernelVersionLess(a, b string) bool {
	na, nb := kernelVersionKey(a), kernelVersionKey(b)
	for i := 0; i < len(na) && i < len(nb); i++ {
		if na[i] != nb[i] {
			return na[i] < nb[i]
		}
	}
	if len(na) != len(nb) {
		return len(na) < len(nb)
	}
	return a < b
}

// kernelVersionKey extracts the ordered list of numeric components from a kernel
// version string (e.g. "6.6.67-0-lts" -> [6 6 67 0]).
func kernelVersionKey(s string) []int {
	var nums []int
	cur := -1
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if cur < 0 {
				cur = 0
			}
			cur = cur*10 + int(r-'0')
		} else if cur >= 0 {
			nums = append(nums, cur)
			cur = -1
		}
	}
	if cur >= 0 {
		nums = append(nums, cur)
	}
	return nums
}

// spotCheckModuleSignatures samples uncompressed .ko files under moduleDir and
// fails if NONE of the sampled modules carry a kernel module signature. Under
// CONFIG_MODULE_SIG_FORCE an unsigned module cannot load, so swapping to a UKI
// whose kernel ships unsigned modules would leave the node unable to bring up
// its hardware — better to keep the old, working UKI. The check is best-effort:
// an unreadable tree, or one with only compressed modules, is skipped (a warning)
// rather than blocking the swap, since it cannot be evaluated cheaply.
func spotCheckModuleSignatures(moduleDir string, logger *logging.Logger) error {
	if _, err := os.Stat(moduleDir); err != nil {
		logger.Warn("[UKI-REBUILD] kernel modules dir not found; skipping module signature spot check", "dir", moduleDir)
		return nil
	}

	var sampled, signed int
	walkErr := filepath.WalkDir(moduleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".ko") {
			return nil
		}
		sampled++
		if ok, _ := fileHasTrailer(path, moduleSignatureMagic); ok {
			signed++
		}
		if sampled >= moduleSpotCheckSampleSize {
			return errStopWalk
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errStopWalk) {
		logger.Warn("[UKI-REBUILD] could not walk kernel modules; skipping signature spot check", "dir", moduleDir, "error", walkErr)
		return nil
	}
	if sampled == 0 {
		logger.Warn("[UKI-REBUILD] no uncompressed kernel modules to spot check; skipping", "dir", moduleDir)
		return nil
	}
	if signed == 0 {
		return &ErrModulesUnsigned{Dir: moduleDir, Sampled: sampled}
	}
	logger.Info("[UKI-REBUILD] kernel module signature spot check passed", "dir", moduleDir, "sampled", sampled, "signed", signed)
	return nil
}

// fileHasTrailer reports whether the file at path ends with trailer.
func fileHasTrailer(path, trailer string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	n := int64(len(trailer))
	if info.Size() < n {
		return false, nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, info.Size()-n); err != nil && err != io.EOF {
		return false, err
	}
	return string(buf) == trailer, nil
}

// copyFile copies src to dst (truncating dst) and fsyncs the result. Used to
// preserve the previous UKI as "<uki>.prev" without ever leaving the live UKI
// path momentarily absent.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
