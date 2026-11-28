//go:build integration

package iso

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPlatformctl writes a shell stand-in for platformctl that records its
// arguments one per line in argsFile and prints a successful iso create
// result, so the adapter's argument building runs without a daemon or ISO.
func stubPlatformctl(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "platformctl")
	argsFile = filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + argsFile + "'; done\n" +
		"printf 'success: true\\noutput_iso: /work/out.iso\\n'\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o755))
	return bin, argsFile
}

func recordedArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestCLIAdapterCreate_NamesStaticInstaller(t *testing.T) {
	bin, argsFile := stubPlatformctl(t)
	res, err := (&CLIAdapter{binaryPath: bin}).Create(context.Background(), CreateOptions{
		WorkDir:               t.TempDir(),
		PlatformctlStaticPath: "/bin/platformctl-static",
	})
	require.NoError(t, err)
	assert.True(t, res.Success)
	assert.Equal(t, "/work/out.iso", res.OutputISO)

	args := recordedArgs(t, argsFile)
	idx := -1
	for i, a := range args {
		if a == "--platformctl-static-binary" {
			idx = i
			break
		}
	}
	require.NotEqual(t, -1, idx, "iso create args lack --platformctl-static-binary: %v", args)
	require.Less(t, idx+1, len(args))
	assert.Equal(t, "/bin/platformctl-static", args[idx+1])
}

func TestCLIAdapterCreate_OmitsStaticInstallerWhenUnset(t *testing.T) {
	bin, argsFile := stubPlatformctl(t)
	_, err := (&CLIAdapter{binaryPath: bin}).Create(context.Background(), CreateOptions{WorkDir: t.TempDir()})
	require.NoError(t, err)
	assert.NotContains(t, recordedArgs(t, argsFile), "--platformctl-static-binary")
}

func TestCreateStaticInstaller_FromEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platformctl-static")
	require.NoError(t, os.WriteFile(path, []byte("static"), 0o755))
	t.Setenv(EnvPlatformCTLStatic, path)
	assert.Equal(t, path, createStaticInstaller(t))
}

func TestRequireNotDynamicInstaller(t *testing.T) {
	refusal := errors.New("CLI call iso create failed: exit status 1: Error: failed to customize ISO: iso: binary /x/platformctl is dynamically linked (interpreter /lib64/ld-linux-x86-64.so.2), the media needs a static one")
	assert.True(t, isDynamicInstallerRefusal(refusal))
	assert.False(t, isDynamicInstallerRefusal(errors.New("exit status 1: mirror unreachable")))
	assert.False(t, isDynamicInstallerRefusal(nil))
}
