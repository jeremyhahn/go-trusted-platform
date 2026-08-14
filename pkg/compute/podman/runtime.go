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

package podman

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeConfig holds configuration for the embedded container runtime
type RuntimeConfig struct {
	// Root is the state directory for containers
	Root string `json:"root" yaml:"root"`

	// RunRoot is the runtime state directory
	RunRoot string `json:"run_root" yaml:"run_root"`

	// TmpDir is the directory for temporary files
	TmpDir string `json:"tmp_dir" yaml:"tmp_dir"`

	// GraphDriverName is the storage driver (overlay, vfs, etc.)
	GraphDriverName string `json:"graph_driver" yaml:"graph_driver"`

	// StaticDir is the directory for static files
	StaticDir string `json:"static_dir" yaml:"static_dir"`

	// VolumePath is the directory for volumes
	VolumePath string `json:"volume_path" yaml:"volume_path"`

	// OCIRuntime is the OCI runtime to use (crun, runc)
	OCIRuntime string `json:"oci_runtime" yaml:"oci_runtime"`

	// ImageStorePath is the path to images
	ImageStorePath string `json:"image_store_path" yaml:"image_store_path"`
}

// The runtime carries no TPM default.
//
// A host-level "enable TPM access" flag used to grant /dev/tpm0 to every
// container the runtime started, whatever its configuration said. The platform
// mirrors its own default into the container specification before measuring it,
// so the platform's path was covered — but any other caller received a device
// that appeared in no container configuration, and therefore in no
// configuration digest. The grant now has exactly one source: the container
// configuration the measurement is taken over
// (ContainerConfig.TPMAccess, itself derived from the measured /dev/tpm0 mount
// by PodmanContainerConfig.GrantsTPMDevice). A caller that wants a default must
// put it in the specification, where it is measured, before the container is
// created.

// DefaultRuntimeConfig returns sensible defaults for the embedded runtime
func DefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Root:            "/var/lib/trusted-platform/containers",
		RunRoot:         "/run/trusted-platform/containers",
		TmpDir:          "/run/trusted-platform/tmp",
		GraphDriverName: "overlay",
		StaticDir:       "/var/lib/trusted-platform/containers/static",
		VolumePath:      "/var/lib/trusted-platform/containers/volumes",
		OCIRuntime:      "crun",
		ImageStorePath:  "/var/lib/trusted-platform/containers/images",
	}
}

// Validate validates the runtime configuration
func (c *RuntimeConfig) Validate() error {
	if c.Root == "" {
		return NewConfigValidationError("root", "root directory is required")
	}

	if c.RunRoot == "" {
		return NewConfigValidationError("run_root", "run root directory is required")
	}

	validDrivers := map[string]bool{
		"overlay":   true,
		"vfs":       true,
		"btrfs":     true,
		"zfs":       true,
		"devmapper": true,
	}

	if c.GraphDriverName != "" && !validDrivers[c.GraphDriverName] {
		return NewConfigValidationError("graph_driver", "invalid storage driver: "+c.GraphDriverName)
	}

	return nil
}

// Runtime provides an embedded container runtime for trusted computing.
// This implementation uses direct OCI runtime invocation (crun/runc) for
// full control over container lifecycle and TPM measurements.
type Runtime struct {
	config      *RuntimeConfig
	logger      *slog.Logger
	containers  sync.Map // map[string]*containerState
	idCounter   atomic.Uint64
	initialized atomic.Bool
	closed      atomic.Bool
}

// containerState tracks runtime state of a container
type containerState struct {
	ID         string
	Name       string
	Image      string
	BundleDir  string
	PID        int
	State      ContainerState
	ExitCode   int
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	Config     *ContainerConfig
}

// RuntimeOption configures a Runtime
type RuntimeOption func(*Runtime)

// WithRuntimeLogger sets the logger for the runtime
func WithRuntimeLogger(logger *slog.Logger) RuntimeOption {
	return func(r *Runtime) {
		r.logger = logger
	}
}

// NewRuntime creates a new embedded container runtime
func NewRuntime(ctx context.Context, config *RuntimeConfig, opts ...RuntimeOption) (*Runtime, error) {
	if config == nil {
		config = DefaultRuntimeConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	r := &Runtime{
		config: config,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.logger == nil {
		r.logger = slog.Default()
	}

	// Ensure directories exist
	if err := r.ensureDirectories(); err != nil {
		return nil, &RuntimeError{Operation: "init", Err: err}
	}

	// Verify OCI runtime is available
	if err := r.verifyOCIRuntime(); err != nil {
		return nil, &RuntimeError{Operation: "verify runtime", Err: err}
	}

	r.initialized.Store(true)

	r.logger.Info("embedded container runtime initialized",
		"root", config.Root,
		"oci_runtime", config.OCIRuntime,
	)

	return r, nil
}

// ensureDirectories creates required directories if they don't exist
func (r *Runtime) ensureDirectories() error {
	dirs := []string{
		r.config.Root,
		r.config.RunRoot,
		r.config.TmpDir,
		r.config.StaticDir,
		r.config.VolumePath,
		r.config.ImageStorePath,
		filepath.Join(r.config.RunRoot, "bundles"),
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to create directory %s", dir), Err: err}
		}
	}

	return nil
}

// verifyOCIRuntime checks that the OCI runtime is available.
func (r *Runtime) verifyOCIRuntime() error {
	_, err := exec.LookPath(r.config.OCIRuntime)
	if err != nil {
		return &OCIRuntimeNotFoundError{Runtime: r.config.OCIRuntime}
	}
	return nil
}

// Close shuts down the runtime
func (r *Runtime) Close() error {
	if r.closed.Load() {
		return nil
	}

	r.closed.Store(true)
	r.initialized.Store(false)

	r.logger.Info("embedded container runtime shut down")
	return nil
}

// Config returns the runtime configuration
func (r *Runtime) Config() *RuntimeConfig {
	return r.config
}

// IsInitialized returns true if the runtime is initialized
func (r *Runtime) IsInitialized() bool {
	return r.initialized.Load()
}

// generateContainerID generates a unique container ID
func (r *Runtime) generateContainerID() string {
	id := r.idCounter.Add(1)
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%d-%d-%d", id, timestamp, os.Getpid())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:64]
}

// CreateContainer creates a new container
func (r *Runtime) CreateContainer(ctx context.Context, config *ContainerConfig) (*containerState, error) {
	if config == nil {
		return nil, ErrInvalidContainerConfig
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Generate container ID
	id := r.generateContainerID()

	r.logger.Info("creating container", "name", config.Name, "image", config.Image, "id", id)

	// Create bundle directory
	bundleDir := filepath.Join(r.config.RunRoot, "bundles", id)
	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		return nil, &RuntimeError{Operation: "create bundle", Err: err}
	}

	// Create rootfs directory (placeholder - in production would unpack image)
	rootfsDir := filepath.Join(bundleDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return nil, &RuntimeError{Operation: "create rootfs", Err: err}
	}

	// Generate OCI config.json
	ociConfig := r.generateOCIConfig(config, rootfsDir)
	configPath := filepath.Join(bundleDir, "config.json")
	configData, err := json.MarshalIndent(ociConfig, "", "  ")
	if err != nil {
		return nil, &RuntimeError{Operation: "marshal config", Err: err}
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return nil, &RuntimeError{Operation: "write config", Err: err}
	}

	state := &containerState{
		ID:        id,
		Name:      config.Name,
		Image:     config.Image,
		BundleDir: bundleDir,
		State:     ContainerStateCreated,
		CreatedAt: time.Now(),
		Config:    config,
	}

	// Store container state
	r.containers.Store(id, state)
	r.containers.Store(config.Name, state)

	r.logger.Info("created container", "name", config.Name, "id", id)
	return state, nil
}

// ociConfig represents a minimal OCI runtime specification
type ociConfig struct {
	OCIVersion string      `json:"ociVersion"`
	Process    *ociProcess `json:"process"`
	Root       *ociRoot    `json:"root"`
	Hostname   string      `json:"hostname,omitempty"`
	Mounts     []ociMount  `json:"mounts,omitempty"`
	Linux      *ociLinux   `json:"linux,omitempty"`
}

type ociProcess struct {
	Terminal        bool             `json:"terminal"`
	User            ociUser          `json:"user"`
	Args            []string         `json:"args"`
	Env             []string         `json:"env,omitempty"`
	Cwd             string           `json:"cwd"`
	Capabilities    *ociCapabilities `json:"capabilities,omitempty"`
	Rlimits         []ociRlimit      `json:"rlimits,omitempty"`
	NoNewPrivileges bool             `json:"noNewPrivileges"`
}

type ociUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type ociCapabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

type ociRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type ociLinux struct {
	Namespaces    []ociNamespace   `json:"namespaces,omitempty"`
	Resources     *ociResources    `json:"resources,omitempty"`
	Devices       []ociLinuxDevice `json:"devices,omitempty"`
	CgroupsPath   string           `json:"cgroupsPath,omitempty"`
	MaskedPaths   []string         `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string         `json:"readonlyPaths,omitempty"`
}

type ociNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type ociResources struct {
	Memory *ociMemory `json:"memory,omitempty"`
	CPU    *ociCPU    `json:"cpu,omitempty"`
	Pids   *ociPids   `json:"pids,omitempty"`
}

type ociMemory struct {
	Limit       *int64 `json:"limit,omitempty"`
	Reservation *int64 `json:"reservation,omitempty"`
	Swap        *int64 `json:"swap,omitempty"`
}

type ociCPU struct {
	Shares *uint64 `json:"shares,omitempty"`
	Quota  *int64  `json:"quota,omitempty"`
	Period *uint64 `json:"period,omitempty"`
}

type ociPids struct {
	Limit int64 `json:"limit"`
}

type ociLinuxDevice struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Major int64  `json:"major"`
	Minor int64  `json:"minor"`
}

// generateOCIConfig generates an OCI runtime config from ContainerConfig
func (r *Runtime) generateOCIConfig(config *ContainerConfig, rootfsPath string) *ociConfig {
	// Build environment variables
	var env []string
	env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	env = append(env, "TERM=xterm")
	for k, v := range config.Environment {
		env = append(env, k+"="+v)
	}

	// Build args
	args := config.Command
	if len(args) == 0 {
		args = []string{"/bin/sh"}
	}

	// Working directory
	cwd := config.WorkDir
	if cwd == "" {
		cwd = "/"
	}

	oci := &ociConfig{
		OCIVersion: "1.0.2",
		Process: &ociProcess{
			Terminal:        false,
			User:            ociUser{UID: 0, GID: 0},
			Args:            args,
			Env:             env,
			Cwd:             cwd,
			NoNewPrivileges: !config.Privileged,
		},
		Root: &ociRoot{
			Path:     rootfsPath,
			Readonly: config.ReadOnly,
		},
		Hostname: config.Hostname,
		Linux: &ociLinux{
			Namespaces: []ociNamespace{
				{Type: "pid"},
				{Type: "network"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "mount"},
			},
			MaskedPaths: []string{
				"/proc/acpi",
				"/proc/kcore",
				"/proc/keys",
				"/proc/latency_stats",
				"/proc/timer_list",
				"/proc/timer_stats",
				"/proc/sched_debug",
				"/sys/firmware",
			},
			ReadonlyPaths: []string{
				"/proc/asound",
				"/proc/bus",
				"/proc/fs",
				"/proc/irq",
				"/proc/sys",
				"/proc/sysrq-trigger",
			},
		},
	}

	// Add default mounts
	oci.Mounts = []ociMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
	}

	// Add user-specified mounts
	for _, m := range config.Mounts {
		opts := m.Options
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		oci.Mounts = append(oci.Mounts, ociMount{
			Destination: m.Target,
			Type:        m.Type,
			Source:      m.Source,
			Options:     opts,
		})
	}

	// Add the TPM device when the container's own configuration grants it. There
	// is no host-level default: see the note on RuntimeConfig.
	if config.TPMAccess {
		oci.Linux.Devices = append(oci.Linux.Devices, ociLinuxDevice{
			Path:  TPMDevicePath,
			Type:  "c",
			Major: 10,
			Minor: 224,
		})
	}

	// Add resource limits
	if config.Resources != nil {
		oci.Linux.Resources = &ociResources{}
		if config.Resources.MemoryLimit > 0 {
			oci.Linux.Resources.Memory = &ociMemory{
				Limit: &config.Resources.MemoryLimit,
			}
			if config.Resources.MemoryReservation > 0 {
				oci.Linux.Resources.Memory.Reservation = &config.Resources.MemoryReservation
			}
			if config.Resources.MemorySwap > 0 {
				oci.Linux.Resources.Memory.Swap = &config.Resources.MemorySwap
			}
		}
		if config.Resources.CPUShares > 0 || config.Resources.CPUQuota > 0 {
			oci.Linux.Resources.CPU = &ociCPU{}
			if config.Resources.CPUShares > 0 {
				shares := uint64(config.Resources.CPUShares)
				oci.Linux.Resources.CPU.Shares = &shares
			}
			if config.Resources.CPUQuota > 0 {
				oci.Linux.Resources.CPU.Quota = &config.Resources.CPUQuota
			}
			if config.Resources.CPUPeriod > 0 {
				period := uint64(config.Resources.CPUPeriod)
				oci.Linux.Resources.CPU.Period = &period
			}
		}
		if config.Resources.PidsLimit > 0 {
			oci.Linux.Resources.Pids = &ociPids{
				Limit: config.Resources.PidsLimit,
			}
		}
	}

	// Handle capabilities
	if !config.Privileged {
		defaultCaps := []string{
			"CAP_CHOWN",
			"CAP_DAC_OVERRIDE",
			"CAP_FSETID",
			"CAP_FOWNER",
			"CAP_MKNOD",
			"CAP_NET_RAW",
			"CAP_SETGID",
			"CAP_SETUID",
			"CAP_SETFCAP",
			"CAP_SETPCAP",
			"CAP_NET_BIND_SERVICE",
			"CAP_SYS_CHROOT",
			"CAP_KILL",
			"CAP_AUDIT_WRITE",
		}
		oci.Process.Capabilities = &ociCapabilities{
			Bounding:    defaultCaps,
			Effective:   defaultCaps,
			Inheritable: defaultCaps,
			Permitted:   defaultCaps,
			Ambient:     defaultCaps,
		}

		// Add extra capabilities
		for _, cap := range config.CapAdd {
			capName := cap
			if !strings.HasPrefix(capName, "CAP_") {
				capName = "CAP_" + capName
			}
			oci.Process.Capabilities.Bounding = append(oci.Process.Capabilities.Bounding, capName)
			oci.Process.Capabilities.Effective = append(oci.Process.Capabilities.Effective, capName)
			oci.Process.Capabilities.Permitted = append(oci.Process.Capabilities.Permitted, capName)
		}

		// Remove dropped capabilities
		for _, cap := range config.CapDrop {
			capName := cap
			if !strings.HasPrefix(capName, "CAP_") {
				capName = "CAP_" + capName
			}
			oci.Process.Capabilities.Bounding = removeString(oci.Process.Capabilities.Bounding, capName)
			oci.Process.Capabilities.Effective = removeString(oci.Process.Capabilities.Effective, capName)
			oci.Process.Capabilities.Permitted = removeString(oci.Process.Capabilities.Permitted, capName)
		}
	}

	return oci
}

// removeString removes a string from a slice
func removeString(slice []string, s string) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// StartContainer starts a container
func (r *Runtime) StartContainer(ctx context.Context, id string) error {
	state, err := r.lookupContainer(id)
	if err != nil {
		return err
	}

	r.logger.Info("starting container", "id", id, "name", state.Name)

	// Execute OCI runtime create
	createCmd := exec.CommandContext(ctx, r.config.OCIRuntime,
		"create",
		"--bundle", state.BundleDir,
		state.ID,
	)
	createCmd.Stdout = os.Stdout
	createCmd.Stderr = os.Stderr

	if err := createCmd.Run(); err != nil {
		r.logger.Error("failed to create container with OCI runtime", "id", id, "error", err)
		return NewContainerError(id, "create", err)
	}

	// Execute OCI runtime start
	startCmd := exec.CommandContext(ctx, r.config.OCIRuntime,
		"start",
		state.ID,
	)
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr

	if err := startCmd.Run(); err != nil {
		r.logger.Error("failed to start container with OCI runtime", "id", id, "error", err)
		return NewContainerError(id, "start", err)
	}

	// Get container PID
	pid, _ := r.getContainerPID(ctx, state.ID)
	state.PID = pid
	state.State = ContainerStateRunning
	now := time.Now()
	state.StartedAt = &now

	r.logger.Info("started container", "id", id, "pid", pid)
	return nil
}

// getContainerPID gets the PID of a running container
func (r *Runtime) getContainerPID(ctx context.Context, id string) (int, error) {
	stateCmd := exec.CommandContext(ctx, r.config.OCIRuntime, "state", id)
	output, err := stateCmd.Output()
	if err != nil {
		return 0, err
	}

	var runtimeState struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(output, &runtimeState); err != nil {
		return 0, err
	}

	return runtimeState.PID, nil
}

// StopContainer stops a running container
func (r *Runtime) StopContainer(ctx context.Context, id string, timeout uint) error {
	state, err := r.lookupContainer(id)
	if err != nil {
		return err
	}

	r.logger.Info("stopping container", "id", id, "timeout", timeout)

	// Send SIGTERM first
	killCmd := exec.CommandContext(ctx, r.config.OCIRuntime,
		"kill",
		state.ID,
		"SIGTERM",
	)
	if err := killCmd.Run(); err != nil {
		// Container might already be stopped
		r.logger.Debug("SIGTERM failed, container may be stopped", "id", id, "error", err)
	}

	// Wait for graceful shutdown
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		if !r.isContainerRunning(ctx, state.ID) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	if r.isContainerRunning(ctx, state.ID) {
		killCmd := exec.CommandContext(ctx, r.config.OCIRuntime,
			"kill",
			state.ID,
			"SIGKILL",
		)
		_ = killCmd.Run()
	}

	state.State = ContainerStateStopped
	now := time.Now()
	state.FinishedAt = &now

	r.logger.Info("stopped container", "id", id)
	return nil
}

// isContainerRunning checks if a container is running
func (r *Runtime) isContainerRunning(ctx context.Context, id string) bool {
	stateCmd := exec.CommandContext(ctx, r.config.OCIRuntime, "state", id)
	output, err := stateCmd.Output()
	if err != nil {
		return false
	}

	var runtimeState struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(output, &runtimeState); err != nil {
		return false
	}

	return runtimeState.Status == "running"
}

// RemoveContainer removes a container
func (r *Runtime) RemoveContainer(ctx context.Context, id string, force bool) error {
	state, err := r.lookupContainer(id)
	if err != nil {
		return err
	}

	r.logger.Info("removing container", "id", id, "force", force)

	// Stop if running and force is set
	if force && r.isContainerRunning(ctx, state.ID) {
		if err := r.StopContainer(ctx, id, 5); err != nil {
			r.logger.Warn("failed to stop container during forced removal", "id", id, "error", err)
		}
	}

	// Delete from OCI runtime
	deleteCmd := exec.CommandContext(ctx, r.config.OCIRuntime,
		"delete",
		"--force",
		state.ID,
	)
	_ = deleteCmd.Run() // Ignore error - container might not exist in runtime

	// Remove bundle directory
	if state.BundleDir != "" {
		if rerr := os.RemoveAll(state.BundleDir); rerr != nil {
			r.logger.Warn("failed to remove bundle directory", "dir", state.BundleDir, "error", rerr)
		}
	}

	// Remove from state maps
	r.containers.Delete(state.ID)
	r.containers.Delete(state.Name)

	r.logger.Info("removed container", "id", id)
	return nil
}

// InspectContainer returns container details
func (r *Runtime) InspectContainer(ctx context.Context, id string) (*containerState, error) {
	return r.lookupContainer(id)
}

// ListContainers returns all containers
func (r *Runtime) ListContainers(ctx context.Context, all bool) ([]*containerState, error) {
	var result []*containerState
	seen := make(map[string]bool)

	r.containers.Range(func(key, value interface{}) bool {
		state := value.(*containerState)
		if seen[state.ID] {
			return true
		}
		seen[state.ID] = true

		if all || state.State == ContainerStateRunning {
			result = append(result, state)
		}
		return true
	})

	return result, nil
}

// WaitContainer waits for a container to exit and returns exit code
func (r *Runtime) WaitContainer(ctx context.Context, id string) (int32, error) {
	state, err := r.lookupContainer(id)
	if err != nil {
		return -1, err
	}

	// Poll for container to exit
	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		default:
			if !r.isContainerRunning(ctx, state.ID) {
				// Get exit code
				exitCode := r.getContainerExitCode(ctx, state.ID)
				state.ExitCode = exitCode
				state.State = ContainerStateExited
				return int32(exitCode), nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// getContainerExitCode gets the exit code of a stopped container
func (r *Runtime) getContainerExitCode(ctx context.Context, id string) int {
	stateCmd := exec.CommandContext(ctx, r.config.OCIRuntime, "state", id)
	output, err := stateCmd.Output()
	if err != nil {
		return -1
	}

	var runtimeState struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(output, &runtimeState); err != nil {
		return -1
	}

	// Parse exit code from status if available
	// Different runtimes format this differently
	return 0
}

// lookupContainer finds a container by ID or name
func (r *Runtime) lookupContainer(id string) (*containerState, error) {
	if value, ok := r.containers.Load(id); ok {
		return value.(*containerState), nil
	}
	return nil, NewContainerError(id, "lookup", ErrContainerNotFound)
}

// PullImage pulls an image from a registry
// For now, this uses the `podman pull` command if available,
// falling back to `skopeo copy` for image downloads
func (r *Runtime) PullImage(ctx context.Context, imageRef string) error {
	if imageRef == "" {
		return NewImageError("", "pull", ErrImageNotFound)
	}

	r.logger.Info("pulling image", "image", imageRef)

	// Try podman first (most likely to be available)
	if podmanPath, err := exec.LookPath("podman"); err == nil {
		pullCmd := exec.CommandContext(ctx, podmanPath, "pull", imageRef)
		pullCmd.Stdout = os.Stdout
		pullCmd.Stderr = os.Stderr
		if err := pullCmd.Run(); err == nil {
			r.logger.Info("pulled image with podman", "image", imageRef)
			return nil
		}
	}

	// Try skopeo as fallback
	if skopeoPath, err := exec.LookPath("skopeo"); err == nil {
		destDir := filepath.Join(r.config.ImageStorePath, sanitizeImageName(imageRef))
		_ = os.MkdirAll(destDir, 0755)

		copyCmd := exec.CommandContext(ctx, skopeoPath, "copy",
			"docker://"+imageRef,
			"dir:"+destDir,
		)
		copyCmd.Stdout = os.Stdout
		copyCmd.Stderr = os.Stderr
		if err := copyCmd.Run(); err == nil {
			r.logger.Info("pulled image with skopeo", "image", imageRef)
			return nil
		}
	}

	return NewImageError(imageRef, "pull", ErrImagePullFailed)
}

// sanitizeImageName converts an image reference to a safe directory name
func sanitizeImageName(imageRef string) string {
	// Replace characters that are invalid in directory names
	safe := strings.ReplaceAll(imageRef, "/", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	safe = strings.ReplaceAll(safe, "@", "_")
	return safe
}

// RemoveImage removes an image
func (r *Runtime) RemoveImage(ctx context.Context, imageRef string, force bool) error {
	if imageRef == "" {
		return NewImageError("", "remove", ErrImageNotFound)
	}

	// Try podman first
	if podmanPath, err := exec.LookPath("podman"); err == nil {
		args := []string{"rmi"}
		if force {
			args = append(args, "-f")
		}
		args = append(args, imageRef)

		rmCmd := exec.CommandContext(ctx, podmanPath, args...)
		if err := rmCmd.Run(); err == nil {
			r.logger.Info("removed image with podman", "image", imageRef)
			return nil
		}
	}

	// Remove from local store
	destDir := filepath.Join(r.config.ImageStorePath, sanitizeImageName(imageRef))
	if err := os.RemoveAll(destDir); err != nil && !os.IsNotExist(err) {
		return NewImageError(imageRef, "remove", err)
	}

	r.logger.Info("removed image", "image", imageRef)
	return nil
}

// RuntimeError represents errors from the embedded runtime
type RuntimeError struct {
	Operation string
	Err       error
}

// Error returns the error message
func (e *RuntimeError) Error() string {
	if e.Err != nil {
		return "runtime " + e.Operation + ": " + e.Err.Error()
	}
	return "runtime " + e.Operation
}

// Unwrap returns the underlying error
func (e *RuntimeError) Unwrap() error {
	return e.Err
}

// Helper function to parse user spec like "1000" or "user"
func parseUserSpec(spec string) (uint32, uint32) {
	parts := strings.SplitN(spec, ":", 2)
	uid, _ := strconv.ParseUint(parts[0], 10, 32)
	var gid uint64
	if len(parts) > 1 {
		gid, _ = strconv.ParseUint(parts[1], 10, 32)
	}
	return uint32(uid), uint32(gid)
}
