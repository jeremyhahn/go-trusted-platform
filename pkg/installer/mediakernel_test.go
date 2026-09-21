package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// writeKernelArtifacts lays out a virt-kernel-builder output directory:
// the kernel, a modules tarball that unpacks lib/modules/<release>, the
// release file and SHA256SUMS over all of it.
func writeKernelArtifacts(t *testing.T, flavor, release string) string {
	t.Helper()
	dir := t.TempDir()
	var tarBuf bytes.Buffer
	gz := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gz)
	body := []byte("module\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "lib/modules/" + release + "/kernel/tpm_tis.ko", Mode: 0o644, Size: int64(len(body))}))
	_, err := tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	files := map[string][]byte{
		"vmlinuz-" + flavor:             []byte("kernel image"),
		"modules-" + flavor + ".tar.gz": tarBuf.Bytes(),
		"kernel-version.txt":            []byte(release + "\n"),
		"config-" + flavor:              []byte("CONFIG_TCG_TIS=y\n"),
	}
	var sums string
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
		sum := sha256.Sum256(data)
		sums += hex.EncodeToString(sum[:]) + "  ./" + name + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644))
	return dir
}

// kernelRunnerRecorder records tar/depmod invocations; tar is executed for
// real (it is what unpacks the modules), depmod is only recorded.
func kernelRunnerRecorder(t *testing.T, calls *[]string, depmodErr error) func(context.Context, string, ...string) ([]byte, error) {
	t.Helper()
	real := mediaKernelRunner
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		if name == "tar" {
			return real(ctx, name, args...)
		}
		if depmodErr != nil {
			return []byte("depmod: boom"), depmodErr
		}
		return nil, nil
	}
}

func newMediaKernelInstaller(t *testing.T, artifacts string) *alpineInstaller {
	t.Helper()
	return &alpineInstaller{
		logger: logging.DefaultLogger(),
		config: &OSConfig{KernelPackage: "linux-virt", KernelArtifactsDir: artifacts},
	}
}

func TestInstallMediaKernel_InstallsKernelModulesAndRunsDepmod(t *testing.T) {
	artifacts := writeKernelArtifacts(t, "virt", "6.12.110-0-virt")
	root := t.TempDir()
	var calls []string
	orig := mediaKernelRunner
	mediaKernelRunner = kernelRunnerRecorder(t, &calls, nil)
	defer func() { mediaKernelRunner = orig }()
	ai := newMediaKernelInstaller(t, artifacts)

	require.NoError(t, ai.installMediaKernel(context.Background(), root))

	kernel, err := os.ReadFile(filepath.Join(root, "boot", "vmlinuz-virt"))
	require.NoError(t, err)
	assert.Equal(t, "kernel image", string(kernel))
	_, err = os.Stat(filepath.Join(root, "lib", "modules", "6.12.110-0-virt", "kernel", "tpm_tis.ko"))
	assert.NoError(t, err, "the modules tarball unpacked at the root")
	require.Len(t, calls, 2)
	assert.Equal(t, "tar -xzf "+filepath.Join(artifacts, "modules-virt.tar.gz")+" -C "+root, calls[0])
	assert.Equal(t, "chroot "+root+" depmod -a 6.12.110-0-virt", calls[1])
}

func TestInstallMediaKernel_Failures(t *testing.T) {
	orig := mediaKernelRunner
	defer func() { mediaKernelRunner = orig }()

	t.Run("tampered artifact", func(t *testing.T) {
		artifacts := writeKernelArtifacts(t, "virt", "6.12.110-0-virt")
		require.NoError(t, os.WriteFile(filepath.Join(artifacts, "vmlinuz-virt"), []byte("evil"), 0o644))
		var calls []string
		mediaKernelRunner = kernelRunnerRecorder(t, &calls, nil)

		err := newMediaKernelInstaller(t, artifacts).installMediaKernel(context.Background(), t.TempDir())

		var installerErr *InstallerError
		require.ErrorAs(t, err, &installerErr)
		assert.Contains(t, err.Error(), "did not verify")
		assert.Empty(t, calls, "nothing is unpacked from artifacts that do not verify")
	})
	t.Run("missing artifacts directory", func(t *testing.T) {
		err := newMediaKernelInstaller(t, filepath.Join(t.TempDir(), "nope")).installMediaKernel(context.Background(), t.TempDir())
		var installerErr *InstallerError
		require.ErrorAs(t, err, &installerErr)
	})
	t.Run("depmod failure", func(t *testing.T) {
		artifacts := writeKernelArtifacts(t, "virt", "6.12.110-0-virt")
		var calls []string
		mediaKernelRunner = kernelRunnerRecorder(t, &calls, errors.New("exit 1"))

		err := newMediaKernelInstaller(t, artifacts).installMediaKernel(context.Background(), t.TempDir())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "depmod failed")
	})
	t.Run("modules tarball for another release", func(t *testing.T) {
		artifacts := writeKernelArtifacts(t, "virt", "6.12.110-0-virt")
		require.NoError(t, os.WriteFile(filepath.Join(artifacts, "kernel-version.txt"), []byte("6.12.111-0-virt\n"), 0o644))
		// Re-sign so the checksum step passes and the release check is what fails.
		sum := sha256.Sum256([]byte("6.12.111-0-virt\n"))
		sums, _ := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
		var rewritten []string
		for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
			if strings.HasSuffix(line, "kernel-version.txt") {
				line = hex.EncodeToString(sum[:]) + "  ./kernel-version.txt"
			}
			rewritten = append(rewritten, line)
		}
		require.NoError(t, os.WriteFile(filepath.Join(artifacts, "SHA256SUMS"), []byte(strings.Join(rewritten, "\n")+"\n"), 0o644))
		var calls []string
		mediaKernelRunner = kernelRunnerRecorder(t, &calls, nil)

		err := newMediaKernelInstaller(t, artifacts).installMediaKernel(context.Background(), t.TempDir())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not produce")
	})
}

func TestErrMediaKernel(t *testing.T) {
	cause := errors.New("cause")
	err := ErrMediaKernel("depmod failed", cause)
	var installerErr *InstallerError
	require.ErrorAs(t, err, &installerErr)
	assert.Equal(t, ErrorTypeOSInstall, installerErr.Type)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "media kernel: depmod failed")
}
