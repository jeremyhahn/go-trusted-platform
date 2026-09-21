package installer

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
)

// mediaKernelRunner runs the two external commands the media kernel
// install needs (tar into the target root, depmod inside it); a variable
// so tests substitute a recorder.
var mediaKernelRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// installMediaKernel installs a platform-built kernel from
// OSConfig.KernelArtifactsDir into the target root: it verifies the
// artifact directory against its SHA256SUMS, copies vmlinuz-<flavor> to
// /boot, unpacks modules-<flavor>.tar.gz at the root and runs depmod for
// the release in kernel-version.txt. The flavour is the configured kernel
// package's (linux-virt -> virt), so the UKI builder's vmlinuz-<flavor>
// lookup and the modules directory look exactly like a packaged kernel.
func (ai *alpineInstaller) installMediaKernel(ctx context.Context, rootPath string) error {
	dir := ai.config.KernelArtifactsDir
	flavor := strings.TrimPrefix(ai.kernelPackage(), "linux-")
	ai.logger.Info("[ALPINE] Installing platform-built kernel from the media", "artifacts", dir, "flavor", flavor)

	if err := artifacts.VerifyChecksums(dir, "run `make virt-kernel-build` and rebuild the media"); err != nil {
		return ErrMediaKernel("kernel artifacts did not verify", err)
	}
	releaseBytes, err := os.ReadFile(filepath.Join(dir, "kernel-version.txt"))
	if err != nil {
		return ErrMediaKernel("kernel-version.txt is missing from the artifacts", err)
	}
	release := strings.TrimSpace(string(releaseBytes))
	if release == "" {
		return ErrMediaKernel("kernel-version.txt is empty", nil)
	}

	bootDir := filepath.Join(rootPath, "boot")
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		return ErrMediaKernel("failed to create /boot", err)
	}
	kernelName := "vmlinuz-" + flavor
	if err := copyFileContents(filepath.Join(dir, kernelName), filepath.Join(bootDir, kernelName)); err != nil {
		return ErrMediaKernel("failed to copy "+kernelName, err)
	}

	modules := filepath.Join(dir, "modules-"+flavor+".tar.gz")
	if out, err := mediaKernelRunner(ctx, "tar", "-xzf", modules, "-C", rootPath); err != nil {
		return ErrMediaKernel("failed to unpack the kernel modules: "+strings.TrimSpace(string(out)), err)
	}
	modulesDir := filepath.Join(rootPath, "lib", "modules", release)
	if _, err := os.Stat(modulesDir); err != nil {
		return ErrMediaKernel("the modules tarball did not produce "+modulesDir, err)
	}
	if out, err := mediaKernelRunner(ctx, "chroot", rootPath, "depmod", "-a", release); err != nil {
		return ErrMediaKernel("depmod failed for "+release+": "+strings.TrimSpace(string(out)), err)
	}
	ai.logger.Info("[ALPINE] Platform-built kernel installed", "kernel", "/boot/"+kernelName, "release", release)
	return nil
}

// copyFileContents copies src to dst (mode 0644), replacing dst.
func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
