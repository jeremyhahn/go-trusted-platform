// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package podman

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOCI describes how the fake OCI runtime script answers each subcommand.
type fakeOCI struct {
	createRC int
	startRC  int
	stateOut string
	stateRC  int
}

// stateRunning is the `state` answer of a running container with PID 4242.
const stateRunning = `{"pid":4242,"status":"running"}`

// writeFakeOCI writes an executable OCI runtime stand-in into a temp dir and
// returns its path. Every subcommand other than create, start and state
// succeeds silently.
func writeFakeOCI(t *testing.T, f fakeOCI) string {
	t.Helper()

	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n"+
		"create) exit %d ;;\n"+
		"start) exit %d ;;\n"+
		"state) printf '%%s' '%s'; exit %d ;;\n"+
		"esac\nexit 0\n", f.createRC, f.startRC, f.stateOut, f.stateRC)

	path := filepath.Join(t.TempDir(), "fake-oci")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// testRuntimeConfig returns a runtime configuration rooted in a temp dir.
func testRuntimeConfig(t *testing.T, ociRuntime string) *RuntimeConfig {
	t.Helper()

	dir := t.TempDir()
	return &RuntimeConfig{
		Root:            dir + "/root",
		RunRoot:         dir + "/run",
		TmpDir:          dir + "/tmp",
		GraphDriverName: "vfs",
		StaticDir:       dir + "/static",
		VolumePath:      dir + "/volumes",
		OCIRuntime:      ociRuntime,
		ImageStorePath:  dir + "/images",
	}
}

// newFakeOCIRuntime builds a Runtime whose OCI runtime is the fake script.
func newFakeOCIRuntime(t *testing.T, f fakeOCI) *Runtime {
	t.Helper()

	rt, err := NewRuntime(context.Background(), testRuntimeConfig(t, writeFakeOCI(t, f)))
	require.NoError(t, err)
	return rt
}

// requireContainerOp asserts err is a ContainerError for the given operation.
func requireContainerOp(t *testing.T, err error, op string) {
	t.Helper()

	var cerr *ContainerError
	require.ErrorAs(t, err, &cerr)
	assert.Equal(t, op, cerr.Operation)
}

func TestRuntimeStartContainer_FakeOCI(t *testing.T) {
	tests := []struct {
		name    string
		oci     fakeOCI
		wantOp  string
		wantPID int
	}{
		{name: "started", oci: fakeOCI{stateOut: stateRunning}, wantPID: 4242},
		{name: "pid unreadable", oci: fakeOCI{stateOut: "not-json"}, wantPID: 0},
		{name: "create fails", oci: fakeOCI{createRC: 1}, wantOp: "create"},
		{name: "start fails", oci: fakeOCI{startRC: 1}, wantOp: "start"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newFakeOCIRuntime(t, tt.oci)
			id := createTestContainer(t, rt, "start-"+strings.ReplaceAll(tt.name, " ", "-"))

			err := rt.StartContainer(context.Background(), id)
			state, lerr := rt.lookupContainer(id)
			require.NoError(t, lerr)

			if tt.wantOp != "" {
				requireContainerOp(t, err, tt.wantOp)
				assert.Equal(t, ContainerStateCreated, state.State)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ContainerStateRunning, state.State)
			assert.Equal(t, tt.wantPID, state.PID)
			assert.NotNil(t, state.StartedAt)
		})
	}
}

func TestRuntimeStartContainer_UnknownContainer(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{stateOut: stateRunning})

	err := rt.StartContainer(context.Background(), "missing")
	require.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeStateQueries_FakeOCI(t *testing.T) {
	tests := []struct {
		name        string
		oci         fakeOCI
		wantRunning bool
		wantPID     int
		wantPIDErr  bool
		wantExit    int
	}{
		{name: "running", oci: fakeOCI{stateOut: stateRunning}, wantRunning: true, wantPID: 4242, wantExit: 0},
		{name: "stopped", oci: fakeOCI{stateOut: `{"pid":7,"status":"stopped"}`}, wantPID: 7, wantExit: 0},
		{name: "invalid json", oci: fakeOCI{stateOut: "garbage"}, wantPIDErr: true, wantExit: -1},
		{name: "state fails", oci: fakeOCI{stateRC: 1}, wantPIDErr: true, wantExit: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newFakeOCIRuntime(t, tt.oci)
			ctx := context.Background()

			assert.Equal(t, tt.wantRunning, rt.isContainerRunning(ctx, "c1"))

			pid, err := rt.getContainerPID(ctx, "c1")
			if tt.wantPIDErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantPID, pid)

			assert.Equal(t, tt.wantExit, rt.getContainerExitCode(ctx, "c1"))
		})
	}
}

func TestRuntimeRemoveContainer_FakeOCI(t *testing.T) {
	tests := []struct {
		name      string
		oci       fakeOCI
		force     bool
		wantState ContainerState
	}{
		{name: "running and forced is stopped first", oci: fakeOCI{stateOut: stateRunning}, force: true, wantState: ContainerStateStopped},
		{name: "running not forced", oci: fakeOCI{stateOut: stateRunning}, wantState: ContainerStateCreated},
		{name: "not running and forced", oci: fakeOCI{stateRC: 1}, force: true, wantState: ContainerStateCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The stop's grace wait sees the container exit at once.
			fakeContainerRunning(t, 0)
			rt := newFakeOCIRuntime(t, tt.oci)
			name := "rm-" + strings.ReplaceAll(tt.name, " ", "-")
			id := createTestContainer(t, rt, name)
			state, err := rt.lookupContainer(id)
			require.NoError(t, err)

			require.NoError(t, rt.RemoveContainer(context.Background(), name, tt.force))

			assert.Equal(t, tt.wantState, state.State)
			assert.NoDirExists(t, state.BundleDir)
			_, err = rt.InspectContainer(context.Background(), id)
			require.ErrorIs(t, err, ErrContainerNotFound)
			_, err = rt.InspectContainer(context.Background(), name)
			require.ErrorIs(t, err, ErrContainerNotFound)
		})
	}
}

func TestRuntimeRemoveContainer_UnknownContainer(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{})

	err := rt.RemoveContainer(context.Background(), "missing", true)
	require.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeListContainers_FiltersRunningAndDeduplicates(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{stateOut: stateRunning})
	ctx := context.Background()
	runningID := createTestContainer(t, rt, "list-running")
	createdID := createTestContainer(t, rt, "list-created")
	require.NoError(t, rt.StartContainer(ctx, runningID))

	all, err := rt.ListContainers(ctx, true)
	require.NoError(t, err)
	ids := make([]string, 0, len(all))
	for _, s := range all {
		ids = append(ids, s.ID)
	}
	assert.ElementsMatch(t, []string{runningID, createdID}, ids)

	running, err := rt.ListContainers(ctx, false)
	require.NoError(t, err)
	require.Len(t, running, 1)
	assert.Equal(t, runningID, running[0].ID)
}

func TestRuntimeInspectContainer_ByIDAndName(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{})
	id := createTestContainer(t, rt, "inspect-me")

	byID, err := rt.InspectContainer(context.Background(), id)
	require.NoError(t, err)
	byName, err := rt.InspectContainer(context.Background(), "inspect-me")
	require.NoError(t, err)
	assert.Same(t, byID, byName)

	_, err = rt.InspectContainer(context.Background(), "nope")
	require.ErrorIs(t, err, ErrContainerNotFound)
}

// fakeImageTool puts an executable named tool on a fresh PATH. The script
// appends its arguments to the returned log file and exits with rc.
func fakeImageTool(t *testing.T, binDir, tool string, rc int) string {
	t.Helper()

	logPath := filepath.Join(binDir, tool+".log")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" >> '%s'\nexit %d\n", logPath, rc)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, tool), []byte(script), 0o755))
	return logPath
}

func readToolLog(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	require.NoError(t, err)
	return strings.TrimSpace(string(data))
}

func TestRuntimePullImage_ToolFallbacks(t *testing.T) {
	tests := []struct {
		name      string
		podmanRC  int // -1: no podman on PATH
		skopeoRC  int // -1: no skopeo on PATH
		wantErr   bool
		wantStore bool
	}{
		{name: "podman pulls", podmanRC: 0, skopeoRC: -1},
		{name: "podman fails then skopeo copies", podmanRC: 1, skopeoRC: 0, wantStore: true},
		{name: "skopeo only", podmanRC: -1, skopeoRC: 0, wantStore: true},
		{name: "both fail", podmanRC: 1, skopeoRC: 1, wantErr: true, wantStore: true},
		{name: "no tools", podmanRC: -1, skopeoRC: -1, wantErr: true},
	}

	const ref = "docker.io/library/alpine:3.20"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newFakeOCIRuntime(t, fakeOCI{})
			binDir := t.TempDir()
			t.Setenv("PATH", binDir)

			var podmanLog, skopeoLog string
			if tt.podmanRC >= 0 {
				podmanLog = fakeImageTool(t, binDir, "podman", tt.podmanRC)
			}
			if tt.skopeoRC >= 0 {
				skopeoLog = fakeImageTool(t, binDir, "skopeo", tt.skopeoRC)
			}

			err := rt.PullImage(context.Background(), ref)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrImagePullFailed)
			} else {
				require.NoError(t, err)
			}

			destDir := filepath.Join(rt.Config().ImageStorePath, sanitizeImageName(ref))
			if tt.wantStore {
				assert.DirExists(t, destDir)
				assert.Equal(t, "copy docker://"+ref+" dir:"+destDir, readToolLog(t, skopeoLog))
			} else {
				assert.NoDirExists(t, destDir)
			}
			if podmanLog != "" {
				assert.Equal(t, "pull "+ref, readToolLog(t, podmanLog))
			}
		})
	}
}

func TestRuntimeRemoveImage_PodmanAndLocalStore(t *testing.T) {
	const ref = "registry.local/app:1"

	tests := []struct {
		name       string
		podmanRC   int // -1: no podman on PATH
		force      bool
		wantArgs   string
		wantStored bool
	}{
		{name: "podman removes with force", podmanRC: 0, force: true, wantArgs: "rmi -f " + ref, wantStored: true},
		{name: "podman removes", podmanRC: 0, wantArgs: "rmi " + ref, wantStored: true},
		{name: "podman fails, local store removed", podmanRC: 1, wantArgs: "rmi " + ref},
		{name: "no podman, local store removed", podmanRC: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newFakeOCIRuntime(t, fakeOCI{})
			binDir := t.TempDir()
			t.Setenv("PATH", binDir)
			var podmanLog string
			if tt.podmanRC >= 0 {
				podmanLog = fakeImageTool(t, binDir, "podman", tt.podmanRC)
			}
			destDir := filepath.Join(rt.Config().ImageStorePath, sanitizeImageName(ref))
			require.NoError(t, os.MkdirAll(destDir, 0o755))

			require.NoError(t, rt.RemoveImage(context.Background(), ref, tt.force))

			if tt.wantStored {
				assert.DirExists(t, destDir)
			} else {
				assert.NoDirExists(t, destDir)
			}
			if podmanLog != "" {
				assert.Equal(t, tt.wantArgs, readToolLog(t, podmanLog))
			}
		})
	}
}

func TestGenerateOCIConfig_ResourcesMountsDevicesAndCaps(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{})
	cfg := &ContainerConfig{
		Name:      "oci",
		Image:     "alpine",
		TPMAccess: true,
		Mounts: []Mount{
			{Source: "/data", Target: "/mnt/data", Type: "bind", ReadOnly: true, Options: []string{"rbind"}},
		},
		Resources: &ResourceLimits{
			MemoryLimit:       512,
			MemoryReservation: 256,
			MemorySwap:        1024,
			CPUShares:         100,
			CPUQuota:          50000,
			CPUPeriod:         100000,
			PidsLimit:         64,
		},
		CapAdd:  []string{"SYS_ADMIN", "CAP_NET_ADMIN"},
		CapDrop: []string{"KILL", "CAP_CHOWN"},
	}

	oci := rt.generateOCIConfig(cfg, "/rootfs")

	mount := oci.Mounts[len(oci.Mounts)-1]
	assert.Equal(t, ociMount{Destination: "/mnt/data", Type: "bind", Source: "/data", Options: []string{"rbind", "ro"}}, mount)

	require.Len(t, oci.Linux.Devices, 1)
	assert.Equal(t, ociLinuxDevice{Path: TPMDevicePath, Type: "c", Major: 10, Minor: 224}, oci.Linux.Devices[0])

	res := oci.Linux.Resources
	require.NotNil(t, res)
	assert.Equal(t, int64(512), *res.Memory.Limit)
	assert.Equal(t, int64(256), *res.Memory.Reservation)
	assert.Equal(t, int64(1024), *res.Memory.Swap)
	assert.Equal(t, uint64(100), *res.CPU.Shares)
	assert.Equal(t, int64(50000), *res.CPU.Quota)
	assert.Equal(t, uint64(100000), *res.CPU.Period)
	assert.Equal(t, int64(64), res.Pids.Limit)

	caps := oci.Process.Capabilities
	for _, set := range [][]string{caps.Bounding, caps.Effective, caps.Permitted} {
		assert.Contains(t, set, "CAP_SYS_ADMIN")
		assert.Contains(t, set, "CAP_NET_ADMIN")
		assert.NotContains(t, set, "CAP_KILL")
		assert.NotContains(t, set, "CAP_CHOWN")
	}
}

func TestGenerateOCIConfig_PrivilegedHasNoCapabilitySet(t *testing.T) {
	rt := newFakeOCIRuntime(t, fakeOCI{})

	oci := rt.generateOCIConfig(&ContainerConfig{
		Name:       "priv",
		Image:      "alpine",
		Privileged: true,
		Resources:  &ResourceLimits{CPUQuota: 1000},
	}, "/rootfs")

	assert.Nil(t, oci.Process.Capabilities)
	assert.False(t, oci.Process.NoNewPrivileges)
	assert.Empty(t, oci.Linux.Devices)
	assert.Nil(t, oci.Linux.Resources.Memory)
	assert.Nil(t, oci.Linux.Resources.CPU.Shares)
	assert.Nil(t, oci.Linux.Resources.CPU.Period)
	assert.Nil(t, oci.Linux.Resources.Pids)
}

func TestDefaultRunOCIExec_CapturesOutputAndExitCode(t *testing.T) {
	result, err := defaultRunOCIExec(context.Background(), "/bin/sh",
		[]string{"-c", "echo out; echo err >&2; exit 3"}, false)
	require.NoError(t, err)
	assert.Equal(t, 3, result.ExitCode)
	assert.Equal(t, "out\n", string(result.Stdout))
	assert.Equal(t, "err\n", string(result.Stderr))
}

func TestDefaultRunOCIExec_MissingRuntime(t *testing.T) {
	result, err := defaultRunOCIExec(context.Background(),
		filepath.Join(t.TempDir(), "no-such-runtime"), nil, false)
	require.Error(t, err)
	assert.Nil(t, result)
}

func TestWrappedError_Unwrap(t *testing.T) {
	err := &WrappedError{Msg: "read cgroup", Err: os.ErrNotExist}

	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, (&WrappedError{Msg: "bare"}).Unwrap())
}

// countingAttestor records how often the manager reports lifecycle events.
type countingAttestor struct {
	testAttestor
	starts atomic.Int32
	stops  atomic.Int32
	err    error
}

func (a *countingAttestor) OnContainerStart(ctx context.Context, container *Container) error {
	a.starts.Add(1)
	return a.err
}

func (a *countingAttestor) OnContainerStop(ctx context.Context, container *Container) error {
	a.stops.Add(1)
	return a.err
}

// newFakeOCIManager returns an initialized manager over the fake OCI runtime.
func newFakeOCIManager(t *testing.T, f fakeOCI, opts ...ManagerOption) *podmanManager {
	t.Helper()

	config := &ManagerConfig{
		Runtime:       testRuntimeConfig(t, writeFakeOCI(t, f)),
		MaxContainers: 10,
	}
	manager, err := NewPodmanManager(config, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	require.NoError(t, manager.Initialize(context.Background()))
	pm := manager.(*podmanManager)
	require.True(t, pm.IsInitialized())
	return pm
}

func TestPodmanManager_LifecycleOverFakeOCI(t *testing.T) {
	for _, attestErr := range []error{nil, ErrContainerNotRunning} {
		t.Run(fmt.Sprintf("attestor error %v", attestErr), func(t *testing.T) {
			fakeContainerRunning(t, 0)
			fakeCgroupFS(t, 4242, map[string]string{"memory.current": "2048\n"})
			attestor := &countingAttestor{err: attestErr}
			m := newFakeOCIManager(t, fakeOCI{stateOut: stateRunning}, WithAttestor(attestor))
			ctx := context.Background()

			// Initialize is idempotent once the runtime is up.
			require.NoError(t, m.Initialize(ctx))

			created, err := m.CreateContainer(ctx, &ContainerConfig{Name: "web", Image: "alpine"})
			require.NoError(t, err)
			assert.Equal(t, int64(1), m.containerCount.Load())

			// An attestor failure is logged and never fails the start or stop.
			require.NoError(t, m.StartContainer(ctx, created.ID))
			assert.Equal(t, int32(1), attestor.starts.Load())

			inspected, err := m.InspectContainer(ctx, "web")
			require.NoError(t, err)
			assert.Equal(t, ContainerStateRunning, inspected.State)
			assert.Equal(t, 4242, inspected.PID)

			running, err := m.ListContainers(ctx, false)
			require.NoError(t, err)
			require.Len(t, running, 1)
			assert.Equal(t, created.ID, running[0].ID)

			stats, err := m.ResourceStats(ctx, created.ID)
			require.NoError(t, err)
			assert.Equal(t, uint64(2048), stats.MemoryUsedBytes)

			zero := 0
			require.NoError(t, m.StopContainer(ctx, inspected.ID, &zero))
			assert.Equal(t, int32(1), attestor.stops.Load())
			cached, ok := m.containers.Load(inspected.ID)
			require.True(t, ok)
			assert.Equal(t, ContainerStateStopped, cached.(*Container).State)
			assert.NotNil(t, cached.(*Container).FinishedAt)

			exitCode, err := m.WaitContainer(ctx, created.ID)
			require.NoError(t, err)
			assert.Equal(t, 0, exitCode)

			require.NoError(t, m.RemoveContainer(ctx, created.ID, false))
			assert.Equal(t, int64(0), m.containerCount.Load())
			_, ok = m.containers.Load("web")
			assert.False(t, ok)
		})
	}
}

func TestPodmanManager_RuntimeErrorsPropagate(t *testing.T) {
	m := newFakeOCIManager(t, fakeOCI{createRC: 1})
	ctx := context.Background()
	zero := 0

	created, err := m.CreateContainer(ctx, &ContainerConfig{Name: "bad", Image: "alpine"})
	require.NoError(t, err)

	requireContainerOp(t, m.StartContainer(ctx, created.ID), "create")
	require.ErrorIs(t, m.StopContainer(ctx, "missing", &zero), ErrContainerNotFound)
	require.ErrorIs(t, m.RemoveContainer(ctx, "missing", false), ErrContainerNotFound)
	_, err = m.InspectContainer(ctx, "missing")
	require.ErrorIs(t, err, ErrContainerNotFound)
	_, err = m.WaitContainer(ctx, "missing")
	require.ErrorIs(t, err, ErrContainerNotFound)
	_, err = m.ResourceStats(ctx, "missing")
	require.ErrorIs(t, err, ErrContainerNotFound)
	_, err = m.CreateContainer(ctx, &ContainerConfig{Name: "no-image"})
	require.Error(t, err)

	all, err := m.ListContainers(ctx, true)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, ContainerStateCreated, all[0].State)
}

func TestPodmanManager_InitializeMissingOCIRuntime(t *testing.T) {
	config := &ManagerConfig{
		Runtime:       testRuntimeConfig(t, filepath.Join(t.TempDir(), "absent-runc")),
		MaxContainers: 1,
	}
	manager, err := NewPodmanManager(config)
	require.NoError(t, err)

	err = manager.Initialize(context.Background())
	var notFound *OCIRuntimeNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.False(t, manager.(*podmanManager).IsInitialized())
	require.ErrorIs(t, manager.StartContainer(context.Background(), "x"), ErrClientNotConnected)
}

func TestPodmanManager_CloseShutsDownRuntime(t *testing.T) {
	m := newFakeOCIManager(t, fakeOCI{})
	rt := m.runtime

	require.NoError(t, m.Close())

	assert.False(t, rt.IsInitialized())
	assert.False(t, m.IsInitialized())
}

func TestPodmanManager_PullImageDelegatesToRuntime(t *testing.T) {
	m := newFakeOCIManager(t, fakeOCI{})
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	ctx := context.Background()

	require.ErrorIs(t, m.PullImage(ctx, "alpine:3.20"), ErrImagePullFailed)

	podmanLog := fakeImageTool(t, binDir, "podman", 0)
	require.NoError(t, m.PullImage(ctx, "alpine:3.20"))
	assert.Equal(t, "pull alpine:3.20", readToolLog(t, podmanLog))
}
