//go:build integration

package diskimage

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// x86Env is the full set of x86 inputs; each case drops or overrides one.
func x86Env() map[string]string {
	return map[string]string{
		"DISKIMAGE_X86_ISO":       "/in/x86.iso",
		"DISKIMAGE_X86_MANIFEST":  "/in/x86.manifest",
		"DISKIMAGE_X86_OVMF_CODE": "/in/OVMF_CODE.fd",
		"DISKIMAGE_X86_OVMF_VARS": "/in/OVMF_VARS.fd",
	}
}

func lookup(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

func TestX86InputsFromEnv(t *testing.T) {
	t.Run("all four variables set resolve", func(t *testing.T) {
		in, err := x86InputsFromEnv(lookup(x86Env()))
		require.NoError(t, err)
		assert.Equal(t, "/in/x86.iso", in.iso)
		assert.Equal(t, "/in/x86.manifest", in.manifest)
		assert.Equal(t, "/in/OVMF_CODE.fd", in.ovmfCode)
		assert.Equal(t, "/in/OVMF_VARS.fd", in.ovmfVars)
	})

	t.Run("ready defaults to login:", func(t *testing.T) {
		in, err := x86InputsFromEnv(lookup(x86Env()))
		require.NoError(t, err)
		assert.Equal(t, "login:", in.ready)
	})

	t.Run("DISKIMAGE_X86_READY overrides the default", func(t *testing.T) {
		env := x86Env()
		env["DISKIMAGE_X86_READY"] = "# "
		in, err := x86InputsFromEnv(lookup(env))
		require.NoError(t, err)
		assert.Equal(t, "# ", in.ready)
	})

	t.Run("each missing variable is a *MissingInputError naming that variable", func(t *testing.T) {
		for _, name := range []string{
			"DISKIMAGE_X86_ISO",
			"DISKIMAGE_X86_MANIFEST",
			"DISKIMAGE_X86_OVMF_CODE",
			"DISKIMAGE_X86_OVMF_VARS",
		} {
			t.Run(name, func(t *testing.T) {
				env := x86Env()
				delete(env, name)
				_, err := x86InputsFromEnv(lookup(env))
				var missing *MissingInputError
				require.True(t, errors.As(err, &missing), "want *MissingInputError, got %v", err)
				assert.Equal(t, name, missing.Variable)
			})
		}
	})
}

func TestX86BootConfig(t *testing.T) {
	in := x86Inputs{
		iso:      "/in/x86.iso",
		manifest: "/in/x86.manifest",
		ovmfCode: "/in/OVMF_CODE.fd",
		ovmfVars: "/in/OVMF_VARS.fd",
		ready:    "login:",
	}
	workDir := "/work/x86"
	cfg := x86BootConfig(in, workDir)

	t.Run("arch is x86_64", func(t *testing.T) {
		assert.Equal(t, qemu.ArchX86_64, cfg.Arch)
	})

	t.Run("the ISO, OVMF code and vars are the inputs'", func(t *testing.T) {
		assert.Equal(t, in.iso, cfg.ISO)
		assert.Equal(t, in.ovmfCode, cfg.OVMFCode)
		assert.Equal(t, in.ovmfVars, cfg.OVMFVars)
	})

	t.Run("boot order is d", func(t *testing.T) {
		assert.Equal(t, "d", cfg.BootOrder)
	})

	t.Run("the console socket and the serial log are under the work dir", func(t *testing.T) {
		assert.Equal(t, workDir, cfg.WorkDir)
		assert.Equal(t, workDir, filepath.Dir(cfg.ConsoleSocketPath))
		assert.Equal(t, workDir, filepath.Dir(cfg.SerialLogFile))
	})

	t.Run("the disk is under the work dir", func(t *testing.T) {
		assert.Equal(t, workDir, filepath.Dir(cfg.DiskPath))
		assert.Equal(t, qemu.DiskFormatQCOW2, cfg.DiskFormat)
	})

	t.Run("no network", func(t *testing.T) {
		assert.Equal(t, "none", cfg.NetworkMode)
	})
}
