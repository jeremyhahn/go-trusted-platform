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

package iso

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// The tests in this file swap the package-level host seams, so none of
// them calls t.Parallel.

var errHost = errors.New("host failure")

// commandFake records every external command the iso verbs build and
// answers it without running anything.
type commandFake struct {
	argv   [][]string
	errs   map[string]error
	output []byte
	// onRun lets a test emulate a command's side effect on the filesystem.
	onRun func(args []string)
	// decide, when set, answers each command in place of errs.
	decide func(args []string) error
}

func (f *commandFake) result(args []string) error {
	if f.decide != nil {
		return f.decide(args)
	}
	return f.errs[args[0]]
}

func withCommandFake(t *testing.T) *commandFake {
	t.Helper()
	f := &commandFake{errs: map[string]error{}}
	run, out := runHostCommand, hostCommandOutput
	t.Cleanup(func() { runHostCommand, hostCommandOutput = run, out })
	runHostCommand = func(cmd *exec.Cmd) error {
		f.argv = append(f.argv, cmd.Args)
		if f.onRun != nil {
			f.onRun(cmd.Args)
		}
		return f.result(cmd.Args)
	}
	hostCommandOutput = func(cmd *exec.Cmd) ([]byte, error) {
		f.argv = append(f.argv, cmd.Args)
		return f.output, f.result(cmd.Args)
	}
	return f
}

// pipelineFake stands in for the Alpine download, extraction, Secure Boot
// key, customization and xorriso steps.
type pipelineFake struct {
	downloads  []*pkgiso.ISOConfig
	extracts   []*pkgiso.ISOConfig
	customized []*pkgiso.PlatformISOConfig
	builds     []*pkgiso.ISOConfig
	decision   pkgiso.SecureBootKeysDecision

	downloadErr, extractErr, keysErr, customizeErr, buildErr error
}

func withPipelineFake(t *testing.T) *pipelineFake {
	t.Helper()
	f := &pipelineFake{decision: pkgiso.SecureBootKeysNotRequested}
	d, e, k, c, b := isoDownload, isoExtract, isoEnsureSecureBootKeys, isoCustomize, isoBuild
	t.Cleanup(func() { isoDownload, isoExtract, isoEnsureSecureBootKeys, isoCustomize, isoBuild = d, e, k, c, b })
	isoDownload = func(_ context.Context, cfg *pkgiso.ISOConfig) error {
		f.downloads = append(f.downloads, cfg)
		return f.downloadErr
	}
	isoExtract = func(_ context.Context, cfg *pkgiso.ISOConfig) error {
		f.extracts = append(f.extracts, cfg)
		if f.extractErr != nil {
			return f.extractErr
		}
		if err := os.MkdirAll(filepath.Join(cfg.ISODir, "boot"), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(cfg.ISODir, "boot", "vmlinuz-lts"), []byte("kernel"), 0o600)
	}
	isoEnsureSecureBootKeys = func(context.Context, *logging.Logger, *pkgiso.ISOBuildConfig) (pkgiso.SecureBootKeysDecision, error) {
		return f.decision, f.keysErr
	}
	isoCustomize = func(_ context.Context, cfg *pkgiso.PlatformISOConfig, _ *logging.Logger) error {
		f.customized = append(f.customized, cfg)
		return f.customizeErr
	}
	isoBuild = func(_ context.Context, _ *logging.Logger, cfg *pkgiso.ISOConfig) error {
		f.builds = append(f.builds, cfg)
		if f.buildErr != nil {
			return f.buildErr
		}
		return os.WriteFile(cfg.OutputISO, []byte("iso image"), 0o600)
	}
	return f
}

// fakeTPM is a started software TPM; only PID and Stop are reached.
type fakeTPM struct {
	harness.TPM
	stopped int
}

func (f *fakeTPM) PID() int    { return 4242 }
func (f *fakeTPM) Stop() error { f.stopped++; return nil }

// fakeEnroller is a Secure Boot key enroller over an in-memory NVRAM.
type fakeEnroller struct {
	enrolled  bool
	enrollErr error
	enrolls   int
}

func (f *fakeEnroller) IsEnrolled() bool { return f.enrolled }
func (f *fakeEnroller) EnrollKeys(context.Context) error {
	f.enrolls++
	return f.enrollErr
}

// vmFake stands in for QEMU and swtpm. Each VM it hands out is a zero
// qemu.VM that is never started.
type vmFake struct {
	configs  []*qemu.Config
	modes    []string
	waits    int
	stops    int
	disks    int
	running  bool
	tapStops []string
	tpm      *fakeTPM
	tpmState harness.TPMState
	tpmStops int
	enroller *fakeEnroller
	enrollerConfigs []*qemu.SecureBootEnrollerConfig

	newErr, startErr, waitErr, stopErr, diskErr, tapErr, tpmErr, enrollerErr error
	// onWait lets a test emulate what the guest wrote before it powered off.
	onWait func(cfg *qemu.Config)
}

func withVMFake(t *testing.T) *vmFake {
	t.Helper()
	f := &vmFake{tpm: &fakeTPM{}, tpmState: harness.TPMStateInitialized, enroller: &fakeEnroller{}}
	newVM, start, wait, stop, disk, running, tap := newQEMUVM, vmStart, vmWait, vmStop, vmCreateDisk, vmIsRunning, stopQEMUByTap
	startT, stopT, enroll := startTPM, stopTPM, newSecureBootEnroller
	t.Cleanup(func() {
		newQEMUVM, vmStart, vmWait, vmStop, vmCreateDisk, vmIsRunning, stopQEMUByTap = newVM, start, wait, stop, disk, running, tap
		startTPM, stopTPM, newSecureBootEnroller = startT, stopT, enroll
	})

	vms := map[*qemu.VM]*qemu.Config{}
	newQEMUVM = func(cfg *qemu.Config, _ *logging.Logger) (*qemu.VM, error) {
		f.configs = append(f.configs, cfg)
		if f.newErr != nil {
			return nil, f.newErr
		}
		vm := &qemu.VM{}
		vms[vm] = cfg
		return vm, nil
	}
	vmStart = func(_ *qemu.VM, _ context.Context, mode string) error {
		f.modes = append(f.modes, mode)
		return f.startErr
	}
	vmWait = func(vm *qemu.VM) error {
		f.waits++
		if f.onWait != nil {
			f.onWait(vms[vm])
		}
		return f.waitErr
	}
	vmStop = func(*qemu.VM) error { f.stops++; return f.stopErr }
	vmCreateDisk = func(*qemu.VM) error { f.disks++; return f.diskErr }
	vmIsRunning = func(*qemu.VM) bool { return f.running }
	stopQEMUByTap = func(tap string) error { f.tapStops = append(f.tapStops, tap); return f.tapErr }

	startTPM = func(context.Context, *logging.Logger, *qemu.Config) (harness.TPM, harness.TPMState, error) {
		if f.tpmErr != nil {
			return nil, "", f.tpmErr
		}
		return f.tpm, f.tpmState, nil
	}
	stopTPM = func(_ *logging.Logger, tpm harness.TPM) {
		if tpm != nil {
			f.tpmStops++
		}
	}
	newSecureBootEnroller = func(cfg *qemu.SecureBootEnrollerConfig, _ *logging.Logger) (secureBootEnroller, error) {
		f.enrollerConfigs = append(f.enrollerConfigs, cfg)
		if f.enrollerErr != nil {
			return nil, f.enrollerErr
		}
		return f.enroller, nil
	}
	return f
}

// withFirmware points the QEMU defaults at an OVMF variable template in a
// temp dir, so NVRAM set-up never reads the host's /usr/share/OVMF.
func withFirmware(t *testing.T) string {
	t.Helper()
	vars := filepath.Join(t.TempDir(), "OVMF_VARS_4M.fd")
	require.NoError(t, os.WriteFile(vars, []byte("ovmf vars"), 0o600))
	orig := defaultQEMUConfig
	t.Cleanup(func() { defaultQEMUConfig = orig })
	defaultQEMUConfig = func() *qemu.Config {
		cfg := orig()
		cfg.OVMFVars = vars
		cfg.NetworkMode = "user"
		return cfg
	}
	return vars
}

// writeInstalledDisk sizes the disk past minInstalledDiskSize, the way a
// finished install leaves it. The file is sparse.
func writeInstalledDisk(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(minInstalledDiskSize+1))
	require.NoError(t, f.Close())
}

func createFlagsFor(t *testing.T, dir string) *createFlags {
	t.Helper()
	withSiblingPlatformd(t)
	return &createFlags{
		arch:            "x86_64",
		platformType:    "client",
		platformVersion: "1.0.0",
		alpineVersion:   "3.21.0",
		workDir:         filepath.Join(dir, "work"),
		output:          filepath.Join(dir, "out.iso"),
	}
}

func TestHostSeams_RunCreatePipeline(t *testing.T) {
	dir := t.TempDir()
	flags := createFlagsFor(t, dir)
	flags.force = true
	pipe := withPipelineFake(t)

	out := new(bytes.Buffer)
	require.NoError(t, runCreate(getTestFlags(), flags, out))

	require.Len(t, pipe.downloads, 1)
	download := pipe.downloads[0]
	assert.Equal(t, "3.21.0", download.Version)
	assert.Equal(t, "x86_64", download.Architecture)
	assert.True(t, download.VerifyChecksum, "the Alpine ISO is always checksum-verified")
	assert.True(t, download.ResumeDownload)

	require.Len(t, pipe.extracts, 1)
	extract := pipe.extracts[0]
	assert.Equal(t, filepath.Base(download.ISOPath()), extract.ISO, "extraction reads the downloaded ISO")
	assert.Equal(t, filepath.Join(download.WorkDir, "iso"), extract.ISODir)

	require.Len(t, pipe.customized, 1)
	require.Len(t, pipe.builds, 1)
	build := pipe.builds[0]
	assert.Equal(t, flags.output, build.OutputISO)
	assert.Equal(t, extract.ISODir, build.ISODir, "the build packs the customized tree")
	assert.NotEmpty(t, build.VolumeID)
	assert.Contains(t, out.String(), flags.output)
}

func TestHostSeams_RunCreateKeyDecisions(t *testing.T) {
	decisions := []pkgiso.SecureBootKeysDecision{
		pkgiso.SecureBootKeysGenerated,
		pkgiso.SecureBootKeysExisting,
		pkgiso.SecureBootKeysRemote,
		pkgiso.SecureBootKeysNotRequested,
		pkgiso.SecureBootKeysDisabled,
	}
	for _, decision := range decisions {
		t.Run(string(decision), func(t *testing.T) {
			flags := createFlagsFor(t, t.TempDir())
			pipe := withPipelineFake(t)
			pipe.decision = decision
			require.NoError(t, runCreate(getTestFlags(), flags, new(bytes.Buffer)))
			assert.Len(t, pipe.builds, 1, "every key decision goes on to build the ISO")
		})
	}
}

func TestHostSeams_RunCreateStepFailures(t *testing.T) {
	tests := []struct {
		name  string
		break_ func(*pipelineFake)
		check func(t *testing.T, err error)
	}{
		{
			name:   "download",
			break_: func(p *pipelineFake) { p.downloadErr = errHost },
			check: func(t *testing.T, err error) {
				var typed ErrDownloadFailed
				require.ErrorAs(t, err, &typed)
				assert.Equal(t, errHost.Error(), typed.Reason)
			},
		},
		{
			name:   "extract",
			break_: func(p *pipelineFake) { p.extractErr = errHost },
			check: func(t *testing.T, err error) {
				var typed ErrExtractionFailed
				require.ErrorAs(t, err, &typed)
				assert.Equal(t, errHost.Error(), typed.Reason)
			},
		},
		{
			name:   "secure boot keys",
			break_: func(p *pipelineFake) { p.keysErr = errHost },
			check: func(t *testing.T, err error) {
				var typed ErrBuildFailed
				require.ErrorAs(t, err, &typed)
				assert.Equal(t, "failed to generate Secure Boot keys: host failure", typed.Reason)
			},
		},
		{
			name:   "customize",
			break_: func(p *pipelineFake) { p.customizeErr = errHost },
			check: func(t *testing.T, err error) {
				var typed ErrCustomizationFailed
				require.ErrorAs(t, err, &typed)
				assert.Equal(t, errHost.Error(), typed.Reason)
			},
		},
		{
			name:   "build",
			break_: func(p *pipelineFake) { p.buildErr = errHost },
			check: func(t *testing.T, err error) {
				var typed ErrBuildFailed
				require.ErrorAs(t, err, &typed)
				assert.Equal(t, errHost.Error(), typed.Reason)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := createFlagsFor(t, t.TempDir())
			pipe := withPipelineFake(t)
			tt.break_(pipe)
			out := new(bytes.Buffer)
			tt.check(t, runCreate(getTestFlags(), flags, out))
			assert.Empty(t, out.String(), "a failed create prints no result")
		})
	}
}

func TestHostSeams_RunBuild(t *testing.T) {
	source := t.TempDir()
	output := filepath.Join(t.TempDir(), "out.iso")

	t.Run("builds and writes the checksum file", func(t *testing.T) {
		pipe := withPipelineFake(t)
		flags := &buildFlags{sourceDir: source, output: output, volumeID: "TRUSTED", generateSum: true}
		out := new(bytes.Buffer)
		require.NoError(t, runBuild(context.Background(), getTestFlags(), flags, out))

		require.Len(t, pipe.builds, 1)
		assert.Equal(t, source, pipe.builds[0].ISODir)
		assert.Equal(t, "TRUSTED", pipe.builds[0].VolumeID)

		sum := sha256.Sum256([]byte("iso image"))
		line, err := os.ReadFile(output + ".sha256")
		require.NoError(t, err)
		assert.Equal(t, hex.EncodeToString(sum[:])+"  out.iso\n", string(line))
		assert.Contains(t, out.String(), hex.EncodeToString(sum[:]))
	})

	t.Run("builder failure", func(t *testing.T) {
		pipe := withPipelineFake(t)
		pipe.buildErr = errHost
		err := runBuild(context.Background(), getTestFlags(), &buildFlags{sourceDir: source, output: output}, new(bytes.Buffer))
		var typed ErrBuildFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, errHost.Error(), typed.Reason)
	})

	t.Run("checksum file cannot be written", func(t *testing.T) {
		withPipelineFake(t)
		blocked := filepath.Join(t.TempDir(), "out.iso")
		require.NoError(t, os.MkdirAll(blocked+".sha256", 0o755))
		err := runBuild(context.Background(), getTestFlags(), &buildFlags{sourceDir: source, output: blocked, generateSum: true}, new(bytes.Buffer))
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to write checksum file", wrapped.Msg)
	})
}

func TestHostSeams_RunCustomize(t *testing.T) {
	platformd := withSiblingPlatformd(t)
	isoDir := t.TempDir()
	flags := &customizeFlags{
		isoDir:          isoDir,
		overlay:         "/srv/overlay",
		workDir:         t.TempDir(),
		platformdPath:   platformd,
	}

	t.Run("customizes the given tree", func(t *testing.T) {
		pipe := withPipelineFake(t)
		out := new(bytes.Buffer)
		require.NoError(t, runCustomize(context.Background(), getTestFlags(), flags, out))
		require.Len(t, pipe.customized, 1)
		assert.Equal(t, isoDir, pipe.customized[0].Directories.ISO)
		assert.Equal(t, "/srv/overlay", pipe.customized[0].Directories.Overlay)
		assert.Contains(t, out.String(), isoDir)
	})

	t.Run("customizer failure", func(t *testing.T) {
		pipe := withPipelineFake(t)
		pipe.customizeErr = errHost
		err := runCustomize(context.Background(), getTestFlags(), flags, new(bytes.Buffer))
		var typed ErrCustomizationFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, errHost.Error(), typed.Reason)
	})
}

func TestHostSeams_RunExtract(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "alpine.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("iso"), 0o600))

	t.Run("extracts and counts the files", func(t *testing.T) {
		pipe := withPipelineFake(t)
		outputDir := filepath.Join(t.TempDir(), "tree")
		out := new(bytes.Buffer)
		require.NoError(t, runExtract(context.Background(), getTestFlags(), &extractFlags{iso: isoPath, outputDir: outputDir}, out))
		require.Len(t, pipe.extracts, 1)
		assert.Equal(t, filepath.Dir(isoPath), pipe.extracts[0].WorkDir)
		assert.Equal(t, "alpine.iso", pipe.extracts[0].ISO)
		assert.Equal(t, outputDir, pipe.extracts[0].ISODir)
		assert.Contains(t, out.String(), outputDir)
	})

	t.Run("extractor failure", func(t *testing.T) {
		pipe := withPipelineFake(t)
		pipe.extractErr = errHost
		err := runExtract(context.Background(), getTestFlags(), &extractFlags{iso: isoPath, outputDir: filepath.Join(t.TempDir(), "tree")}, new(bytes.Buffer))
		var typed ErrExtractionFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, errHost.Error(), typed.Reason)
	})
}

func builderConfigFor(t *testing.T) *ISOBuilderConfig {
	t.Helper()
	dir := t.TempDir()
	platformd := filepath.Join(dir, "platformd")
	require.NoError(t, os.WriteFile(platformd, []byte("#!/bin/true\n"), 0o700))
	webUI := filepath.Join(dir, "public_html.tar.gz")
	require.NoError(t, os.WriteFile(webUI, []byte("ui"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keys"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("ca"), 0o600))
	return &ISOBuilderConfig{
		WorkDir:         filepath.Join(dir, "work"),
		OutputPath:      filepath.Join(dir, "server.iso"),
		PlatformdBinary: platformd,
		PlatformType:    "client",
		WebUIPath:       webUI,
		KeysDir:         filepath.Join(dir, "keys"),
		CABundlePath:    filepath.Join(dir, "ca.pem"),
	}
}

func TestHostSeams_BuildCustomISO(t *testing.T) {
	logger := createTestLogger(false)

	t.Run("runs every step", func(t *testing.T) {
		cfg := builderConfigFor(t)
		pipe := withPipelineFake(t)
		pipe.decision = pkgiso.SecureBootKeysGenerated
		require.NoError(t, BuildCustomISO(context.Background(), logger, cfg))
		require.Len(t, pipe.downloads, 1)
		require.Len(t, pipe.extracts, 1)
		require.Len(t, pipe.customized, 1)
		require.Len(t, pipe.builds, 1)
		assert.Equal(t, cfg.OutputPath, pipe.builds[0].OutputISO)
		assert.Equal(t, cfg.KeysDir, pipe.builds[0].KeysDir)
	})

	tests := []struct {
		name   string
		break_ func(*pipelineFake)
		msg    string
	}{
		{"download", func(p *pipelineFake) { p.downloadErr = errHost }, "failed to download Alpine ISO"},
		{"extract", func(p *pipelineFake) { p.extractErr = errHost }, "failed to extract ISO"},
		{"secure boot keys", func(p *pipelineFake) { p.keysErr = errHost }, "failed to generate Secure Boot keys"},
		{"customize", func(p *pipelineFake) { p.customizeErr = errHost }, "failed to customize ISO"},
		{"build", func(p *pipelineFake) { p.buildErr = errHost }, "failed to build final ISO"},
	}
	for _, tt := range tests {
		t.Run(tt.name+" fails", func(t *testing.T) {
			cfg := builderConfigFor(t)
			pipe := withPipelineFake(t)
			pipe.decision = pkgiso.SecureBootKeysRemote
			tt.break_(pipe)
			err := BuildCustomISO(context.Background(), logger, cfg)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.msg, wrapped.Msg)
			assert.ErrorIs(t, err, errHost)
		})
	}
}

func TestHostSeams_BuildCustomISOPlatformdBinary(t *testing.T) {
	logger := createTestLogger(false)

	t.Run("relative path resolves against the working directory", func(t *testing.T) {
		pipe := withPipelineFake(t)
		cfg := builderConfigFor(t)
		absolute := cfg.PlatformdBinary
		t.Chdir(filepath.Dir(absolute))
		cfg.PlatformdBinary = "platformd"

		require.NoError(t, BuildCustomISO(context.Background(), logger, cfg))

		require.Len(t, pipe.customized, 1)
		assert.Equal(t, absolute, pipe.customized[0].Platform.PlatformdBinary)
	})

	t.Run("missing binary", func(t *testing.T) {
		pipe := withPipelineFake(t)
		cfg := builderConfigFor(t)
		cfg.PlatformdBinary = filepath.Join(t.TempDir(), "platformd")

		err := BuildCustomISO(context.Background(), logger, cfg)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "platformd binary not found: "+cfg.PlatformdBinary, msg.Msg)
		assert.Empty(t, pipe.downloads)
	})

	t.Run("without a binary the running executable must be platformd", func(t *testing.T) {
		pipe := withPipelineFake(t)
		cfg := builderConfigFor(t)
		cfg.PlatformdBinary = ""

		err := BuildCustomISO(context.Background(), logger, cfg)
		var name *pkgiso.ErrPlatformdBinaryName
		require.ErrorAs(t, err, &name)
		assert.Equal(t, "binary does not appear to be platformd", name.Reason)
		assert.Empty(t, pipe.downloads, "nothing is downloaded for the wrong binary")
	})
}

func TestHostSeams_ResolveWebUIAutoBuild(t *testing.T) {
	logger := createTestLogger(false)
	makeArgv := []string{"make", "build-public-html"}

	t.Run("make fails", func(t *testing.T) {
		t.Chdir(t.TempDir())
		cmds := withCommandFake(t)
		cmds.errs["make"] = errHost
		path, err := resolveWebUIPath(context.Background(), logger, "")
		var cmdErr *CommandOutputError
		require.ErrorAs(t, err, &cmdErr)
		assert.Equal(t, "failed to auto-build WebUI", cmdErr.Msg)
		assert.Empty(t, path)
		assert.Equal(t, [][]string{makeArgv}, cmds.argv)
	})

	t.Run("make produces the tarball", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		cmds := withCommandFake(t)
		cmds.onRun = func([]string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "public_html.tar.gz"), []byte("ui"), 0o600))
		}
		path, err := resolveWebUIPath(context.Background(), logger, "")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(dir, "public_html.tar.gz"), path)
		assert.Equal(t, [][]string{makeArgv}, cmds.argv)
	})

	t.Run("make produces the directory", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		cmds := withCommandFake(t)
		cmds.onRun = func([]string) {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "public_html"), 0o755))
		}
		path, err := resolveWebUIPath(context.Background(), logger, "")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(dir, "public_html"), path)
	})

	t.Run("make produces nothing", func(t *testing.T) {
		t.Chdir(t.TempDir())
		withCommandFake(t)
		path, err := resolveWebUIPath(context.Background(), logger, "")
		require.NoError(t, err)
		assert.Empty(t, path, "the ISO is built without a WebUI")
	})
}

func installFlagsFor(t *testing.T) *testFlags {
	t.Helper()
	dir := t.TempDir()
	iso := filepath.Join(dir, "trusted.iso")
	require.NoError(t, os.WriteFile(iso, []byte("iso"), 0o600))
	return &testFlags{
		iso:       iso,
		disk:      filepath.Join(dir, "disk.qcow2"),
		diskSize:  "8G",
		memory:    1024,
		cpus:      1,
		workDir:   filepath.Join(dir, "work"),
	}
}

func TestHostSeams_RunTestInstall(t *testing.T) {
	t.Run("installs onto the disk", func(t *testing.T) {
		withFirmware(t)
		flags := installFlagsFor(t)
		cmds := withCommandFake(t)
		vms := withVMFake(t)
		vms.onWait = func(cfg *qemu.Config) { writeInstalledDisk(t, cfg.DiskPath) }

		require.NoError(t, runTestInstall(getTestFlags(), flags))

		assert.Equal(t, [][]string{{"qemu-img", "create", "-f", "qcow2", flags.disk, "8G"}}, cmds.argv)
		require.Len(t, vms.configs, 1)
		assert.Equal(t, flags.iso, vms.configs[0].ISO)
		assert.Equal(t, []string{string(qemu.BootModeInstall)}, vms.modes)
		assert.Equal(t, 1, vms.tpmStops, "the software TPM is stopped after the install")
		_, err := os.Stat(vms.configs[0].GetNVRAMPath())
		assert.NoError(t, err, "a fresh NVRAM is copied from the firmware template")
	})

	t.Run("guest powers off without writing the disk", func(t *testing.T) {
		withFirmware(t)
		flags := installFlagsFor(t)
		withCommandFake(t)
		withVMFake(t)
		err := runTestInstall(getTestFlags(), flags)
		var typed ErrInstallDiskNotWritten
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, flags.disk, typed.Disk)
	})

	tests := []struct {
		name  string
		setup func(t *testing.T, flags *testFlags, cmds *commandFake, vms *vmFake)
		msg   string
	}{
		{
			name: "work dir under a file",
			setup: func(t *testing.T, flags *testFlags, _ *commandFake, _ *vmFake) {
				file := filepath.Join(t.TempDir(), "file")
				require.NoError(t, os.WriteFile(file, nil, 0o600))
				flags.workDir = filepath.Join(file, "work")
			},
			msg: "failed to setup VM environment",
		},
		{
			name: "qemu-img fails",
			setup: func(_ *testing.T, _ *testFlags, cmds *commandFake, _ *vmFake) {
				cmds.errs["qemu-img"] = errHost
			},
			msg: "failed to create disk image",
		},
		{
			name: "swtpm fails",
			setup: func(_ *testing.T, _ *testFlags, _ *commandFake, vms *vmFake) {
				vms.tpmErr = errHost
			},
			msg: "failed to setup TPM",
		},
		{
			name: "key enrollment fails",
			setup: func(t *testing.T, flags *testFlags, _ *commandFake, vms *vmFake) {
				flags.secureBoot = true
				require.NoError(t, os.MkdirAll(filepath.Join(flags.workDir, "secure-boot-keys"), 0o755))
				vms.enroller.enrollErr = errHost
			},
			msg: "failed to enroll Secure Boot keys",
		},
		{
			name: "QEMU fails to start",
			setup: func(_ *testing.T, _ *testFlags, _ *commandFake, vms *vmFake) {
				vms.startErr = errHost
			},
			msg: "QEMU installation failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFirmware(t)
			flags := installFlagsFor(t)
			cmds := withCommandFake(t)
			vms := withVMFake(t)
			tt.setup(t, flags, cmds, vms)
			err := runTestInstall(getTestFlags(), flags)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.msg, wrapped.Msg)
			assert.NotNil(t, wrapped.Err, "the cause is kept")
		})
	}

	t.Run("NVRAM template missing", func(t *testing.T) {
		vars := withFirmware(t)
		require.NoError(t, os.Remove(vars))
		flags := installFlagsFor(t)
		withCommandFake(t)
		withVMFake(t)
		err := runTestInstall(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to setup VM environment", wrapped.Msg,
			"a first run copies the template while setting up the environment")
	})
}

func TestHostSeams_RunTestBoot(t *testing.T) {
	bootFlags := func(t *testing.T) *testFlags {
		flags := installFlagsFor(t)
		require.NoError(t, os.WriteFile(flags.disk, []byte("disk"), 0o600))
		return flags
	}

	t.Run("boots the installed disk", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		vms := withVMFake(t)
		require.NoError(t, runTestBoot(getTestFlags(), flags, "Normal Boot Test"))
		assert.Equal(t, []string{string(qemu.BootModeBoot)}, vms.modes)
		assert.Equal(t, 1, vms.waits)
		assert.Equal(t, flags.disk, vms.configs[0].DiskPath)
	})

	t.Run("guest exits with an error", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		vms := withVMFake(t)
		vms.waitErr = errHost
		err := runTestFirstBoot(getTestFlags(), flags, "First Boot Test")
		var typed *ErrBootFailed
		require.ErrorAs(t, err, &typed)
		assert.ErrorIs(t, err, errHost)
	})

	t.Run("VM cannot be created", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		vms := withVMFake(t)
		vms.newErr = errHost
		err := runTestBoot(getTestFlags(), flags, "Normal Boot Test")
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create VM", wrapped.Msg)
	})

	t.Run("VM does not start", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		vms := withVMFake(t)
		vms.startErr = errHost
		err := runTestBoot(getTestFlags(), flags, "Normal Boot Test")
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to start VM", wrapped.Msg)
	})

	t.Run("swtpm fails", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		vms := withVMFake(t)
		vms.tpmErr = errHost
		err := runTestBoot(getTestFlags(), flags, "Normal Boot Test")
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to setup TPM", wrapped.Msg)
	})

	t.Run("key enrollment fails", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		flags.secureBoot = true
		require.NoError(t, os.MkdirAll(filepath.Join(flags.workDir, "iso-build", "secure-boot-keys"), 0o755))
		vms := withVMFake(t)
		vms.enrollerErr = errHost
		err := runTestBoot(getTestFlags(), flags, "Normal Boot Test")
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to enroll Secure Boot keys", wrapped.Msg)
	})

	t.Run("work dir under a file", func(t *testing.T) {
		withFirmware(t)
		flags := bootFlags(t)
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		flags.workDir = filepath.Join(file, "work")
		withVMFake(t)
		err := runTestBoot(getTestFlags(), flags, "Normal Boot Test")
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to setup VM environment", wrapped.Msg)
	})
}

func TestHostSeams_RunTestAll(t *testing.T) {
	t.Run("install, first boot and boot", func(t *testing.T) {
		withFirmware(t)
		flags := installFlagsFor(t)
		withCommandFake(t)
		vms := withVMFake(t)
		vms.onWait = func(cfg *qemu.Config) { writeInstalledDisk(t, cfg.DiskPath) }
		require.NoError(t, runTestAll(getTestFlags(), flags))
		assert.Equal(t, []string{
			string(qemu.BootModeInstall), string(qemu.BootModeBoot), string(qemu.BootModeBoot),
		}, vms.modes)
	})

	t.Run("first boot fails", func(t *testing.T) {
		withFirmware(t)
		flags := installFlagsFor(t)
		withCommandFake(t)
		vms := withVMFake(t)
		vms.onWait = func(cfg *qemu.Config) {
			writeInstalledDisk(t, cfg.DiskPath)
			vms.newErr = errHost // every VM after the install fails to create
		}
		err := runTestAll(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "first boot test failed", wrapped.Msg)
	})
}

func TestHostSeams_EnrollSecureBootKeys(t *testing.T) {
	logger := createTestLogger(false)
	config := func(t *testing.T) *qemu.Config {
		cfg := qemu.DefaultConfig()
		cfg.WorkDir = t.TempDir()
		cfg.SecureBoot = true
		cfg.OVMFVars = "/firmware/OVMF_VARS.fd"
		require.NoError(t, os.MkdirAll(filepath.Join(cfg.WorkDir, "secure-boot-keys"), 0o755))
		return cfg
	}

	t.Run("enrolls the work dir keys", func(t *testing.T) {
		cfg := config(t)
		vms := withVMFake(t)
		require.NoError(t, enrollTestSecureBootKeys(context.Background(), logger, cfg))
		require.Len(t, vms.enrollerConfigs, 1)
		assert.Equal(t, filepath.Join(cfg.WorkDir, "secure-boot-keys"), vms.enrollerConfigs[0].KeysDir)
		assert.Equal(t, filepath.Join(cfg.WorkDir, "nvram"), vms.enrollerConfigs[0].NVRAMDir)
		assert.Equal(t, "/firmware/OVMF_VARS.fd", vms.enrollerConfigs[0].OVMFVarsPath)
		assert.Equal(t, 1, vms.enroller.enrolls)
	})

	t.Run("already enrolled keeps the NVRAM", func(t *testing.T) {
		cfg := config(t)
		vms := withVMFake(t)
		vms.enroller.enrolled = true
		require.NoError(t, enrollTestSecureBootKeys(context.Background(), logger, cfg))
		assert.Zero(t, vms.enroller.enrolls)
	})

	t.Run("enroller cannot be created", func(t *testing.T) {
		cfg := config(t)
		vms := withVMFake(t)
		vms.enrollerErr = errHost
		err := enrollTestSecureBootKeys(context.Background(), logger, cfg)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create Secure Boot enroller", wrapped.Msg)
	})

	t.Run("no keys directory skips enrollment", func(t *testing.T) {
		cfg := qemu.DefaultConfig()
		cfg.WorkDir = t.TempDir()
		cfg.SecureBoot = true
		vms := withVMFake(t)
		require.NoError(t, enrollTestSecureBootKeys(context.Background(), logger, cfg))
		assert.Empty(t, vms.enrollerConfigs)
	})
}

func TestHostSeams_SetupTestTPMReportsState(t *testing.T) {
	logger := createTestLogger(false)
	for _, state := range []harness.TPMState{harness.TPMStateInitialized, harness.TPMStatePreserved} {
		t.Run(string(state), func(t *testing.T) {
			vms := withVMFake(t)
			vms.tpmState = state
			tpm, err := setupTestTPM(context.Background(), logger, qemu.DefaultConfig())
			require.NoError(t, err)
			assert.Equal(t, 4242, tpm.PID())
		})
	}
}

func TestHostSeams_SetupTestVMEnvironmentReusesNVRAM(t *testing.T) {
	logger := createTestLogger(false)
	cfg := qemu.DefaultConfig()
	cfg.WorkDir = t.TempDir()
	cfg.OVMFVars = filepath.Join(t.TempDir(), "absent.fd")
	nvram := cfg.GetNVRAMPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(nvram), 0o755))
	require.NoError(t, os.WriteFile(nvram, []byte("enrolled"), 0o600))

	require.NoError(t, setupTestVMEnvironment(context.Background(), logger, cfg),
		"an existing NVRAM is kept, so the template is never read")
	got, err := os.ReadFile(nvram)
	require.NoError(t, err)
	assert.Equal(t, "enrolled", string(got))

	t.Run("reset replaces it from the template", func(t *testing.T) {
		vars := filepath.Join(t.TempDir(), "vars.fd")
		require.NoError(t, os.WriteFile(vars, []byte("fresh"), 0o600))
		cfg.OVMFVars = vars
		require.NoError(t, resetTestNVRAM(context.Background(), logger, cfg))
		got, err := os.ReadFile(nvram)
		require.NoError(t, err)
		assert.Equal(t, "fresh", string(got))
	})

	t.Run("reset without a template", func(t *testing.T) {
		cfg.OVMFVars = filepath.Join(t.TempDir(), "absent.fd")
		err := resetTestNVRAM(context.Background(), logger, cfg)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to initialize NVRAM", wrapped.Msg)
	})

	t.Run("aarch64 has no NVRAM", func(t *testing.T) {
		arm := qemu.DefaultConfig()
		arm.WorkDir = t.TempDir()
		arm.Arch = qemu.ArchAArch64
		arm.OVMFVars = filepath.Join(t.TempDir(), "absent.fd")
		require.NoError(t, setupTestVMEnvironment(context.Background(), logger, arm))
	})
}

func TestHostSeams_SeamedVMDelegates(t *testing.T) {
	vms := withVMFake(t)
	vms.waitErr = errHost
	vm := seamedVM{vm: &qemu.VM{}}
	assert.ErrorIs(t, vm.Wait(), errHost)
	require.NoError(t, vm.Stop())
	assert.Equal(t, 1, vms.waits)
	assert.Equal(t, 1, vms.stops)
}
