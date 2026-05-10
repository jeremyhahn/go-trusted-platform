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

package deployer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// LinuxDeployer deploys the bootstrap container to a Linux host via SSH.
type LinuxDeployer struct {
	logger *slog.Logger
}

// NewLinuxDeployer constructs a LinuxDeployer backed by the given
// logger. The deployer is stateless beyond the logger; SSH connections
// are established per-Deploy / per-Verify / per-Teardown call.
func NewLinuxDeployer(logger *slog.Logger) *LinuxDeployer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LinuxDeployer{logger: logger}
}

// Deploy connects to the Linux host via SSH, stages all required PXE
// assets into config.DataDir, pulls the container image, and runs the
// bootstrap container with --net=host -v <DataDir>:/data.
//
// Asset staging is a critical correctness step: the bootstrap container
// image ships /data/vmlinuz, /data/initramfs, and /data/autoinstall.sh
// baked at image-build time. The bind-mount overlays /data with the host
// DataDir, hiding the baked files. We extract them out of the image into
// the host DataDir BEFORE starting the container so they remain visible
// once the bind-mount is in place. The manifest.yaml the orchestrator
// generated is placed in the same directory.
//
// Asset extraction uses `docker create` + `docker cp` (works under both
// docker and podman) and runs entirely on the deployer host so we don't
// have to ship a multi-MB initramfs over SSH.
//
// Pre-existing containers with the same name are torn down before
// re-deploy. The caller is responsible for honouring RedeployMode (the
// orchestrator gates this via Verify before invoking Deploy); Deploy
// itself is unconditionally destructive on the named container so the
// final state is deterministic.
func (d *LinuxDeployer) Deploy(ctx context.Context, config *DeployConfig) (*DeployResult, error) {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	d.logger.Info("connected to deploy target",
		slog.String("host", config.Host),
		slog.Int("port", config.Port))

	// Create remote data directory. configs/ is for per-MAC YAML overrides
	// (autoinstall.sh fetches /config/mac/<mac>/hostname etc.); the parent
	// holds manifest.yaml, vmlinuz, initramfs, autoinstall.sh.
	mkdirCmd := fmt.Sprintf("mkdir -p %s/configs", shellQuote(config.DataDir))
	if _, err := client.Run(ctx, mkdirCmd); err != nil {
		return nil, err
	}

	// Copy manifest file.
	remoteManifest := fmt.Sprintf("%s/manifest.yaml", config.DataDir)
	if err := client.CopyFile(ctx, config.ManifestPath, remoteManifest); err != nil {
		return nil, err
	}
	d.logger.Info("copied manifest", slog.String("remote_path", remoteManifest))

	// Pull the container image — but ONLY when it's not already
	// present locally. Operators commonly build the bootstrap-pxe
	// image on the deployer jumpbox itself (e.g. via
	// `make pxeboot-image` or a local docker build) so that no remote
	// registry is involved. In that case `docker pull` fails with
	// "pull access denied" because the image tag doesn't exist on
	// any registry the daemon is configured to consult, even though
	// the local image is perfectly serviceable.
	//
	// The flow: probe with `docker image inspect <ref>` first; on
	// success, skip the pull entirely. On miss, attempt the pull and
	// surface the error verbatim so registry/credential issues are
	// reported clearly to the operator.
	inspectCmd := fmt.Sprintf("%s image inspect %s >/dev/null 2>&1",
		shellQuote(config.ContainerRuntime), shellQuote(config.ContainerImage))
	if _, inspectErr := client.Run(ctx, inspectCmd); inspectErr == nil {
		d.logger.Info("container image present locally — skipping pull",
			slog.String("image", config.ContainerImage))
	} else {
		pullCmd := fmt.Sprintf("%s pull %s",
			shellQuote(config.ContainerRuntime), shellQuote(config.ContainerImage))
		if _, err := client.Run(ctx, pullCmd); err != nil {
			return nil, err
		}
		d.logger.Info("pulled container image", slog.String("image", config.ContainerImage))
	}

	// Tear down any pre-existing container of the same name. Idempotent:
	// returns successfully when no container exists. The orchestrator's
	// RedeployMode gate already decided we should land here; once we do,
	// the named container is replaced unconditionally.
	teardownCmd := fmt.Sprintf("%s rm -f %s 2>/dev/null || true",
		shellQuote(config.ContainerRuntime), shellQuote(config.ContainerName))
	if _, err := client.Run(ctx, teardownCmd); err != nil {
		// "|| true" makes errors here unexpected, but log and continue —
		// the docker run below will surface the real failure if the old
		// container is somehow still present.
		d.logger.Warn("pre-deploy teardown returned error (non-fatal)",
			slog.String("error", err.Error()))
	}

	// Extract image-baked PXE assets into the host DataDir so the
	// upcoming bind-mount doesn't shadow them. We create a throw-away
	// container from the image (no run), copy each file out, then remove
	// the placeholder. This pattern works under both docker and podman.
	if err := d.stagePXEAssets(ctx, client, config); err != nil {
		return nil, err
	}

	// Run the container.
	runCmd := GenerateRunCommand(config)
	output, err := client.Run(ctx, runCmd)
	if err != nil {
		return nil, err
	}

	containerID := strings.TrimSpace(output)
	d.logger.Info("started bootstrap container",
		slog.String("container_id", containerID),
		slog.String("host", config.Host))

	return &DeployResult{
		ContainerID: containerID,
		Host:        config.Host,
		Running:     true,
	}, nil
}

// stagePXEAssets extracts image-baked /data files into the host DataDir
// using `<runtime> create` + `<runtime> cp`. The fundamental problem this
// solves: the container image's `/data/vmlinuz`, `/data/initramfs`, and
// `/data/autoinstall.sh` are populated at build time, but the container
// is started with `-v <DataDir>:/data`, which overlays those files with
// the (possibly empty) host directory. pxeboot inside then fails to find
// its kernel/initrd. By copying the files out FIRST we make them visible
// through the overlay.
//
// Files that don't exist in the image are silently skipped (no warning):
// older bootstrap images may not ship every file in this list, and the
// Phase 5 hand-off path doesn't need them.
func (d *LinuxDeployer) stagePXEAssets(ctx context.Context, client *SSHClient, config *DeployConfig) error {
	const stagerName = "trusted-bootstrap-asset-stager"

	// Required image paths the bootstrap container expects to find under
	// /data at startup.  Empty subpaths are silently skipped — older
	// images may not ship every asset.
	assets := []string{
		"vmlinuz",
		"initramfs",
		"autoinstall.sh",
	}

	// Best-effort cleanup of any prior stager container left behind by an
	// interrupted run. `|| true` keeps the failure path quiet; if rm is
	// genuinely broken, the create below will surface a clearer error.
	cleanupCmd := fmt.Sprintf("%s rm -f %s 2>/dev/null || true",
		shellQuote(config.ContainerRuntime), shellQuote(stagerName))
	if _, err := client.Run(ctx, cleanupCmd); err != nil {
		d.logger.Warn("asset-stager pre-cleanup returned error (non-fatal)",
			slog.String("error", err.Error()))
	}

	createCmd := fmt.Sprintf("%s create --name %s %s /bin/true",
		shellQuote(config.ContainerRuntime),
		shellQuote(stagerName),
		shellQuote(config.ContainerImage))
	if _, err := client.Run(ctx, createCmd); err != nil {
		return ErrAssetStageFailed{Phase: "create", Cause: err}
	}
	defer func() {
		rmCmd := fmt.Sprintf("%s rm -f %s",
			shellQuote(config.ContainerRuntime), shellQuote(stagerName))
		if _, rmErr := client.Run(ctx, rmCmd); rmErr != nil {
			d.logger.Warn("asset-stager cleanup failed (non-fatal)",
				slog.String("error", rmErr.Error()))
		}
	}()

	for _, asset := range assets {
		// `docker cp` returns 1 with "No such file or directory" when the
		// asset isn't in the image. We tolerate that — but distinguish it
		// from a real cp failure by checking stderr after the run.
		cpCmd := fmt.Sprintf("%s cp %s:/data/%s %s/%s 2>&1",
			shellQuote(config.ContainerRuntime),
			shellQuote(stagerName),
			asset,
			shellQuote(config.DataDir),
			asset)
		out, err := client.Run(ctx, cpCmd)
		if err == nil {
			d.logger.Info("staged image asset",
				slog.String("asset", asset),
				slog.String("data_dir", config.DataDir))
			continue
		}
		// docker cp prints "Error: No such file or directory" or
		// "Error response from daemon: Could not find the file ..." when
		// the asset is missing. Treat that as "image doesn't ship this
		// asset" rather than a hard failure.
		if isMissingAssetError(out) {
			d.logger.Debug("image does not ship asset, skipping",
				slog.String("asset", asset))
			continue
		}
		return ErrAssetStageFailed{Phase: "cp:" + asset, Cause: err}
	}
	return nil
}

// shellQuote single-quotes a string for safe inclusion in a remote shell
// command. Existing single quotes are escaped via the standard
// '\''-style trick; this is sufficient for paths, runtime names, and
// container/image identifiers (none of which legitimately contain
// shell-meta characters).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isMissingAssetError checks the runtime's `cp` stderr output for the
// well-known "asset not in image" signatures. Both docker and podman
// emit recognisable variants when an inner path doesn't exist.
func isMissingAssetError(stderr string) bool {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "no such file or directory"),
		strings.Contains(s, "could not find the file"),
		strings.Contains(s, "no such file"),
		strings.Contains(s, "does not exist in container"):
		return true
	}
	return false
}

// Verify checks that the bootstrap container is running on the target
// host AND that its image and bind-mount source match what the current
// DeployConfig expects. Returns:
//
//   - nil when a container with the configured name is running with the
//     expected image and bind mount.
//   - ErrContainerNotRunning when no container exists or it isn't running.
//   - ErrContainerStateMismatch when a container of the configured name
//     exists but with a different image or bind-mount source. The
//     orchestrator's RedeployMode interprets this:
//       * RedeployAlways → ignore the error, redeploy
//       * RedeployIfStale → ignore the error, redeploy
//       * RedeployNever → propagate the error to the operator
func (d *LinuxDeployer) Verify(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return err
	}

	// Single inspect call returning Running + Image + bind source so we
	// don't pay three SSH round-trips for what should be a fast probe.
	// Tab-separated so we can parse without quoting each field.
	const fmtRunningImageBind = `{{.State.Running}}	{{.Config.Image}}	{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}`
	inspectCmd := fmt.Sprintf("%s inspect --format %s %s",
		shellQuote(config.ContainerRuntime),
		shellQuote(fmtRunningImageBind),
		shellQuote(config.ContainerName))
	output, err := client.Run(ctx, inspectCmd)
	if err != nil {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}

	parts := strings.SplitN(strings.TrimSpace(output), "\t", 3)
	if len(parts) < 3 {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}
	running, gotImage, gotBind := parts[0], parts[1], parts[2]

	if running != "true" {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}
	if gotImage != config.ContainerImage {
		return ErrContainerStateMismatch{
			ContainerID: config.ContainerName,
			Host:        config.Host,
			Field:       "image",
			Want:        config.ContainerImage,
			Got:         gotImage,
		}
	}
	if gotBind != config.DataDir {
		return ErrContainerStateMismatch{
			ContainerID: config.ContainerName,
			Host:        config.Host,
			Field:       "bind-mount",
			Want:        config.DataDir,
			Got:         gotBind,
		}
	}

	d.logger.Info("container verified running",
		slog.String("host", config.Host),
		slog.String("container", config.ContainerName))
	return nil
}

// Teardown stops and removes the bootstrap container and data from the
// target host. Only the SSH connection fields are required; manifest_path
// and container_image are deploy-time inputs that the teardown path
// doesn't read, so we use ValidateTeardown rather than Validate.
func (d *LinuxDeployer) Teardown(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()
	if err := config.ValidateTeardown(); err != nil {
		return err
	}

	client, err := NewSSHClient(config.Host, config.Port, config.User, config.SSHKeyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return err
	}

	teardownCmd := GenerateTeardownCommand(config)
	if _, err := client.Run(ctx, teardownCmd); err != nil {
		d.logger.Warn("teardown command returned error",
			slog.String("error", err.Error()))
	}

	d.logger.Info("teardown complete",
		slog.String("host", config.Host),
		slog.String("container", DefaultContainerName))
	return nil
}

// GenerateRunCommand builds the container run command string. Honours
// DataDir + ContainerName + the full Bootstrap* network env from the
// config (DataDir and ContainerName default-filled by ApplyDefaults;
// the Bootstrap* fields are optional and fall through to the image
// entrypoint's defaults when empty).
func GenerateRunCommand(config *DeployConfig) string {
	envFlags := bootstrapEnvFlags(config)
	return fmt.Sprintf(
		"%s run -d --name %s --net=host%s -v %s:/data %s",
		shellQuote(config.ContainerRuntime),
		shellQuote(config.ContainerName),
		envFlags,
		shellQuote(config.DataDir),
		shellQuote(config.ContainerImage),
	)
}

// bootstrapEnvFlags renders the -e VAR=val arguments for every set
// Bootstrap* field on the DeployConfig. Empty fields are skipped so
// the container's entrypoint defaults take effect, matching the
// "override only what's needed" deploy contract.
func bootstrapEnvFlags(config *DeployConfig) string {
	pairs := []struct {
		name, value string
	}{
		{"BOOTSTRAP_INTERFACE", config.BootstrapInterface},
		{"BOOTSTRAP_SERVER_IP", config.BootstrapServerIP},
		{"BOOTSTRAP_DHCP_START", config.BootstrapDHCPStart},
		{"BOOTSTRAP_DHCP_END", config.BootstrapDHCPEnd},
		{"BOOTSTRAP_GATEWAY", config.BootstrapGateway},
		{"BOOTSTRAP_DNS", config.BootstrapDNS},
	}
	var b strings.Builder
	for _, p := range pairs {
		v := strings.TrimSpace(p.value)
		if v == "" {
			continue
		}
		b.WriteString(" -e ")
		b.WriteString(p.name)
		b.WriteString("=")
		b.WriteString(shellQuote(v))
	}
	return b.String()
}

// GenerateTeardownCommand builds the container teardown command string.
// Honours ContainerName + DataDir from the config.
func GenerateTeardownCommand(config *DeployConfig) string {
	return fmt.Sprintf(
		"%s rm -f %s && rm -rf %s",
		shellQuote(config.ContainerRuntime),
		shellQuote(config.ContainerName),
		shellQuote(config.DataDir),
	)
}
