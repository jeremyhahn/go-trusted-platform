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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// remoteImageTar is the deterministic path on the remote host where the
// orchestrator stages a locally-built image tar before `<runtime> load`.
// It lives under /tmp so it's independent of DataDir creation order and is
// removed best-effort after the load completes.
const remoteImageTar = "/tmp/.pxeboot-image-load.tar"

// localRunner executes a command on the deployer host (where the
// orchestrator runs). Injectable so unit tests avoid real docker.
type localRunner interface {
	run(ctx context.Context, name string, args ...string) (string, error)
}

// execLocalRunner is the production localRunner; it shells out to the
// named binary on the orchestrator host and returns combined output.
type execLocalRunner struct{}

func (execLocalRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// LinuxDeployer deploys the bootstrap container to a Linux host via SSH.
type LinuxDeployer struct {
	logger *slog.Logger
	// local runs container-runtime commands on the orchestrator host so
	// the deployer can resolve and ship locally-built images. Defaults to
	// execLocalRunner{}; unit tests inject a fake.
	local localRunner
	// dial builds the RemoteHost for a deploy config's transport.
	// Defaults to NewRemoteHost (SSH, or the QUIC deploy agent).
	dial RemoteHostFactory
}

// NewLinuxDeployer constructs a LinuxDeployer backed by the given
// logger. The deployer is stateless beyond the logger; SSH connections
// are established per-Deploy / per-Verify / per-Teardown call.
func NewLinuxDeployer(logger *slog.Logger) *LinuxDeployer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LinuxDeployer{logger: logger, local: execLocalRunner{}, dial: NewRemoteHost}
}

// connect builds the RemoteHost for config's transport and connects it.
// The caller closes it.
func (d *LinuxDeployer) connect(ctx context.Context, config *DeployConfig) (RemoteHost, error) {
	dial := d.dial
	if dial == nil {
		dial = NewRemoteHost
	}
	client, err := dial(config)
	if err != nil {
		return nil, err
	}
	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// Deploy connects to the Linux host via SSH, stages the manifest and the
// netboot media build into config.DataDir, ships/pulls the container
// image, and runs the bootstrap container with --net=host -v <DataDir>:/data.
// The image carries no installer media: everything it serves under /data
// is staged here.
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

	client, err := d.connect(ctx, config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	d.logger.Info("connected to deploy target",
		slog.String("host", config.Host),
		slog.String("transport", config.Transport))

	if _, err := client.Run(ctx, GeneratePrepareCommand(config)); err != nil {
		return nil, err
	}

	// Copy manifest file.
	remoteManifest := fmt.Sprintf("%s/manifest.yaml", config.DataDir)
	if err := copySmallFile(ctx, client, config.ManifestPath, remoteManifest); err != nil {
		return nil, err
	}
	d.logger.Info("copied manifest", slog.String("remote_path", remoteManifest))

	// Ship a locally-built image to the remote, or pull from a registry.
	// The tar staging path lives under /tmp so it's independent of the
	// DataDir mkdir above.
	if err := d.shipOrPullImage(ctx, client, config); err != nil {
		return nil, err
	}

	// Replace any pre-existing container of the same name. The
	// orchestrator's RedeployMode gate already decided we should land
	// here; once we do, the named container is replaced unconditionally.
	if _, err := client.Run(ctx, GenerateReplaceCommand(config)); err != nil {
		// "|| true" makes errors here unexpected, but log and continue —
		// the docker run below will surface the real failure if the old
		// container is somehow still present.
		d.logger.Warn("pre-deploy teardown returned error (non-fatal)",
			slog.String("error", err.Error()))
	}

	// Stage the netboot media build — every media set, the Raspberry Pi
	// stage and the arm64 iPXE; its index says which TFTP tree and arm64
	// iPXE the container is to serve.
	paths, err := stageNetbootMedia(ctx, client, config.NetbootMediaDir, config.DataDir, d.logger)
	if err != nil {
		return nil, err
	}
	config.netboot = paths

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

// smallFileCopier is the optional RemoteHost capability for copying a
// small file (manifest, config) in one command. The SSH transport has it
// (base64 through the shell, no upload subsystem needed on the target);
// the QUIC agent does not, and streams every file.
type smallFileCopier interface {
	CopyFile(ctx context.Context, localPath, remotePath string) error
}

// copySmallFile copies a small local file to the target with the host's
// one-command copy when it has one, and streams it otherwise.
func copySmallFile(ctx context.Context, host RemoteHost, localPath, remotePath string) error {
	if c, ok := host.(smallFileCopier); ok {
		return c.CopyFile(ctx, localPath, remotePath)
	}
	return host.CopyFileStream(ctx, localPath, remotePath)
}

// shipOrPullImage makes the configured image available on the remote
// host before the container is run.
//
// Operators commonly build the bootstrap image locally on the
// orchestrator host (where platformctl runs) rather than push it to a
// registry. In that case the image exists ONLY on the orchestrator and
// must be shipped to the remote jumpbox; a plain remote `pull` would fail
// with "pull access denied", and a stale remote tag of the same name
// would otherwise be silently reused with old code.
//
// Resolution order:
//
//  1. Resolve the LOCAL image ID on the orchestrator host.
//  2. If a local image exists, compare it to the remote image ID and ship
//     (save | stream | load) only when they differ; skip when equal.
//  3. If no local image exists, fall back to the legacy remote
//     inspect-or-pull path so registry-based deploys keep working.
func (d *LinuxDeployer) shipOrPullImage(ctx context.Context, client RemoteStager, config *DeployConfig) error {
	localID := d.localImageID(ctx, config.ContainerRuntime, config.ContainerImage)

	if localID != "" {
		remoteID := d.remoteImageID(ctx, client, config.ContainerRuntime, config.ContainerImage)
		if remoteID == localID {
			d.logger.Info("remote image matches local image, skipping ship",
				slog.String("image", config.ContainerImage),
				slog.String("image_id", localID))
			return nil
		}
		return d.shipImage(ctx, client, config, localID)
	}

	// No local image on the orchestrator host: preserve the legacy remote
	// inspect-or-pull behaviour verbatim so registry deploys (and hosts
	// without docker locally) keep working. Probe with `image inspect`
	// first; on success skip the pull, otherwise pull and surface registry
	// errors verbatim.
	inspectCmd := fmt.Sprintf("%s image inspect %s >/dev/null 2>&1",
		shellQuote(config.ContainerRuntime), shellQuote(config.ContainerImage))
	if _, inspectErr := client.Run(ctx, inspectCmd); inspectErr == nil {
		d.logger.Info("container image present on remote — skipping pull",
			slog.String("image", config.ContainerImage))
		return nil
	}
	pullCmd := fmt.Sprintf("%s pull %s",
		shellQuote(config.ContainerRuntime), shellQuote(config.ContainerImage))
	if _, err := client.Run(ctx, pullCmd); err != nil {
		return err
	}
	d.logger.Info("pulled container image", slog.String("image", config.ContainerImage))
	return nil
}

// shipImage saves the locally-built image to a temporary tar on the
// orchestrator host, streams it to the remote, and loads it there. Each
// phase wraps its failure in ErrImageShipFailed. The remote tar is
// removed best-effort after a successful load.
func (d *LinuxDeployer) shipImage(ctx context.Context, client RemoteStager, config *DeployConfig, localID string) error {
	d.logger.Info("shipping locally-built image to remote host",
		slog.String("image", config.ContainerImage),
		slog.String("image_id", localID),
		slog.String("host", config.Host))

	// 1. Save the local image to a temporary tar on the orchestrator host.
	tmp, err := os.CreateTemp("", "pxeboot-image-*.tar")
	if err != nil {
		return ErrImageShipFailed{Phase: "save:tempfile", Cause: err}
	}
	tmpPath := tmp.Name()
	// `<runtime> save -o` writes the file itself, so release our handle.
	if cErr := tmp.Close(); cErr != nil {
		_ = os.Remove(tmpPath)
		return ErrImageShipFailed{Phase: "save:tempfile", Cause: cErr}
	}
	defer func() {
		if rmErr := os.Remove(tmpPath); rmErr != nil {
			d.logger.Warn("local image tar cleanup failed (non-fatal)",
				slog.String("path", tmpPath),
				slog.String("error", rmErr.Error()))
		}
	}()

	if out, saveErr := d.local.run(ctx, config.ContainerRuntime,
		"save", "-o", tmpPath, config.ContainerImage); saveErr != nil {
		d.logger.Warn("local image save failed",
			slog.String("output", strings.TrimSpace(out)))
		return ErrImageShipFailed{Phase: "save", Cause: saveErr}
	}
	d.logger.Info("saved local image to tar", slog.String("tar", tmpPath))

	// 2. Stream the tar to the remote host.
	if copyErr := client.CopyFileStream(ctx, tmpPath, remoteImageTar); copyErr != nil {
		return ErrImageShipFailed{Phase: "copy", Cause: copyErr}
	}
	d.logger.Info("copied image tar to remote", slog.String("remote_tar", remoteImageTar))

	// 3. Load the image on the remote host.
	if _, loadErr := client.Run(ctx, GenerateImageLoadCommand(config.ContainerRuntime, remoteImageTar)); loadErr != nil {
		return ErrImageShipFailed{Phase: "load", Cause: loadErr}
	}
	d.logger.Info("loaded image on remote host", slog.String("image", config.ContainerImage))

	// 4. Best-effort cleanup of the remote tar (non-fatal).
	rmCmd := fmt.Sprintf("rm -f %s", shellQuote(remoteImageTar))
	if _, rmErr := client.Run(ctx, rmCmd); rmErr != nil {
		d.logger.Warn("remote image tar cleanup failed (non-fatal)",
			slog.String("error", rmErr.Error()))
	}
	return nil
}

// localImageID resolves the image ID of config.ContainerImage on the
// orchestrator host via the injected localRunner. Any error (no docker,
// image absent) is treated as "no local image" — an empty ID — and logged
// at Debug so the legacy remote inspect-or-pull path can take over.
func (d *LinuxDeployer) localImageID(ctx context.Context, runtime, image string) string {
	out, err := d.local.run(ctx, runtime, localImageInspectArgs(image)...)
	if err != nil {
		d.logger.Debug("local image inspect failed; treating as no local image",
			slog.String("image", image),
			slog.String("error", err.Error()))
		return ""
	}
	return strings.TrimSpace(out)
}

// remoteImageID resolves the image ID of image on the remote host. Any
// error (image absent) is treated as "no remote image" — an empty ID —
// and logged at Debug. The {{.Id}} format matches localImageID so the
// two strings are directly comparable.
func (d *LinuxDeployer) remoteImageID(ctx context.Context, client RemoteStager, runtime, image string) string {
	out, err := client.Run(ctx, remoteImageInspectCmd(runtime, image))
	if err != nil {
		d.logger.Debug("remote image inspect failed; treating as no remote image",
			slog.String("image", image),
			slog.String("error", err.Error()))
		return ""
	}
	return strings.TrimSpace(out)
}

// localImageInspectArgs returns the argv (after the runtime name) for
// resolving an image ID on the orchestrator host. The {{.Id}} format is
// kept identical to the remote inspect so the IDs are comparable.
func localImageInspectArgs(image string) []string {
	return []string{"image", "inspect", "--format", "{{.Id}}", image}
}

// remoteImageInspectCmd builds the remote shell command that resolves an
// image ID over SSH. Uses the same {{.Id}} format as localImageInspectArgs
// so the resulting strings can be compared directly.
func remoteImageInspectCmd(runtime, image string) string {
	return fmt.Sprintf("%s image inspect --format %s %s",
		shellQuote(runtime), shellQuote("{{.Id}}"), shellQuote(image))
}

// GenerateImageLoadCommand builds the remote shell command that loads a
// previously-streamed image tar, e.g. 'docker' load -i '<tar>'. Both the
// runtime and tar path are shell-quoted for safe remote execution.
func GenerateImageLoadCommand(runtime, remoteTarPath string) string {
	return fmt.Sprintf("%s load -i %s", shellQuote(runtime), shellQuote(remoteTarPath))
}

// shellQuote single-quotes a string for safe inclusion in a remote shell
// command. Existing single quotes are escaped via the standard
// '\”-style trick; this is sufficient for paths, runtime names, and
// container/image identifiers (none of which legitimately contain
// shell-meta characters).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// verifyInspectFormat is the single `inspect --format` template Verify
// runs, so the probe costs one SSH round-trip. Fields are tab-separated
// so they parse without quoting: running, image tag, image ID, the /data
// bind source, the restart policy, and the firmware cache bind source.
var verifyInspectFormat = strings.Join([]string{
	"{{.State.Running}}",
	"{{.Config.Image}}",
	"{{.Image}}",
	mountSourceFormat("/data"),
	"{{.HostConfig.RestartPolicy.Name}}",
	mountSourceFormat(ContainerFirmwareCacheDir),
}, "\t")

// verifyInspectFields is the number of fields verifyInspectFormat emits.
const verifyInspectFields = 6

// mountSourceFormat returns the inspect template that prints the host
// source of the mount whose container destination is dest, or nothing
// when no such mount exists.
func mountSourceFormat(dest string) string {
	return `{{range .Mounts}}{{if eq .Destination "` + dest + `"}}{{.Source}}{{end}}{{end}}`
}

// inspectState is the container state Verify reads back from inspect.
type inspectState struct {
	Running       string
	Image         string
	ImageID       string
	DataBind      string
	RestartPolicy string
	FirmwareBind  string
}

// parseVerifyInspect parses one line of verifyInspectFormat output.
// Leading/trailing CR/LF on the whole line and surrounding whitespace on
// each field are trimmed. ok is false when fewer than six fields are
// present (e.g. the container does not exist and inspect emitted nothing
// parseable).
func parseVerifyInspect(output string) (inspectState, bool) {
	line := strings.Trim(output, "\r\n")
	parts := strings.SplitN(line, "\t", verifyInspectFields)
	if len(parts) < verifyInspectFields {
		return inspectState{}, false
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return inspectState{
		Running:       parts[0],
		Image:         parts[1],
		ImageID:       parts[2],
		DataBind:      parts[3],
		RestartPolicy: parts[4],
		FirmwareBind:  parts[5],
	}, true
}

// stateCheck is one inspected field compared against its configured value.
type stateCheck struct {
	field string
	want  string
	got   string
}

// checkContainerState compares the inspected state with config. It
// returns ErrContainerNotRunning for a stopped container and
// ErrContainerStateMismatch naming the first field that differs. The
// restart policy and the firmware cache mount are checked only in
// boot-node mode, so switching boot_node on makes a running default-mode
// container stale and the if-stale redeploy replaces it.
func checkContainerState(config *DeployConfig, got inspectState) error {
	if got.Running != "true" {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}
	checks := []stateCheck{
		{"image", config.ContainerImage, got.Image},
		{"bind-mount", config.DataDir, got.DataBind},
	}
	if config.BootNode {
		checks = append(checks,
			stateCheck{"restart-policy", bootNodeRestartPolicy, got.RestartPolicy},
			stateCheck{"firmware-cache", config.FirmwareCacheDir, got.FirmwareBind},
		)
	}
	for _, c := range checks {
		if c.want != c.got {
			return ErrContainerStateMismatch{
				ContainerID: config.ContainerName,
				Host:        config.Host,
				Field:       c.field,
				Want:        c.want,
				Got:         c.got,
			}
		}
	}
	return nil
}

// imageStale reports whether a running container's image is stale relative
// to the local image. It returns true ONLY when both IDs are non-empty
// and differ. An empty localID (the orchestrator host has no local image)
// is deliberately treated as "not stale" so the legacy registry-based flow
// is preserved.
func imageStale(localID, runningID string) bool {
	if localID == "" || runningID == "" {
		return false
	}
	return localID != runningID
}

// Verify checks that the bootstrap container is running on the target
// host AND that its image and bind-mount source match what the current
// DeployConfig expects. Returns:
//
//   - nil when a container with the configured name is running with the
//     expected image and bind mount.
//   - ErrContainerNotRunning when no container exists or it isn't running.
//   - ErrContainerStateMismatch when a container of the configured name
//     exists but with a different image (tag or digest) or bind-mount
//     source. The orchestrator's RedeployMode interprets this:
//   - RedeployAlways → ignore the error, redeploy
//   - RedeployIfStale → ignore the error, redeploy
//   - RedeployNever → propagate the error to the operator
//
// Verify-before-Deploy ordering constraint: the adapter calls Verify
// BEFORE Deploy, so a freshly-rebuilt local image has NOT been shipped to
// the remote yet. The remote tag (Config.Image) is therefore also stale
// until Deploy ships it, which is why the digest staleness check compares
// the running container's image ID against the LOCAL image ID resolved on
// the orchestrator host — not against the remote tag. This is what makes
// RedeployIfStale trigger a redeploy after a local rebuild.
func (d *LinuxDeployer) Verify(ctx context.Context, config *DeployConfig) error {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}

	client, err := d.connect(ctx, config)
	if err != nil {
		return err
	}
	defer client.Close()

	inspectCmd := fmt.Sprintf("%s inspect --format %s %s",
		shellQuote(config.ContainerRuntime),
		shellQuote(verifyInspectFormat),
		shellQuote(config.ContainerName))
	output, err := client.Run(ctx, inspectCmd)
	if err != nil {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}

	got, ok := parseVerifyInspect(output)
	if !ok {
		return ErrContainerNotRunning{ContainerID: config.ContainerName, Host: config.Host}
	}
	if err := checkContainerState(config, got); err != nil {
		return err
	}

	// Digest staleness: compare the running container's image ID against
	// the LOCAL image ID (see the ordering rationale above). An absent
	// local image yields localID="" → imageStale is false → preserve the
	// tag-only behaviour for registry-based deploys.
	localID := d.localImageID(ctx, config.ContainerRuntime, config.ContainerImage)
	if imageStale(localID, got.ImageID) {
		return ErrContainerStateMismatch{
			ContainerID: config.ContainerName,
			Host:        config.Host,
			Field:       "image-digest",
			Want:        localID,
			Got:         got.ImageID,
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

	client, err := d.connect(ctx, config)
	if err != nil {
		return err
	}
	defer client.Close()

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
// GeneratePrepareCommand builds the command that creates the remote host
// directories the container mounts. configs/ under DataDir holds per-MAC
// YAML overrides (autoinstall.sh fetches /config/mac/<mac>/hostname etc.);
// DataDir itself holds manifest.yaml and the netboot media build. In
// boot-node mode the firmware cache directory is created too, because
// podman refuses a bind mount whose source does not exist. mkdir -p never
// removes anything, so a re-deploy keeps both volumes' contents.
func GeneratePrepareCommand(config *DeployConfig) string {
	cmd := "mkdir -p " + shellQuote(config.DataDir+"/configs")
	if config.BootNode {
		cmd += " " + shellQuote(config.FirmwareCacheDir)
	}
	return cmd
}

// GenerateReplaceCommand builds the command Deploy runs before starting
// the container: it removes any container of the same name and nothing
// else, so the host volumes survive a re-deploy. Idempotent: it succeeds
// when no container exists.
func GenerateReplaceCommand(config *DeployConfig) string {
	return fmt.Sprintf("%s rm -f %s 2>/dev/null || true",
		shellQuote(config.ContainerRuntime), shellQuote(config.ContainerName))
}

func GenerateRunCommand(config *DeployConfig) string {
	envFlags := bootstrapEnvFlags(config)
	return fmt.Sprintf(
		"%s run -d --name %s%s --net=host%s -v %s:/data%s %s",
		shellQuote(config.ContainerRuntime),
		shellQuote(config.ContainerName),
		bootNodeRestartFlag(config),
		envFlags,
		shellQuote(config.DataDir),
		bootNodeVolumeFlag(config),
		shellQuote(config.ContainerImage),
	)
}

// bootNodeRestartFlag is the run flag that brings a boot node's container
// back after a crash or a host reboot; empty outside boot-node mode.
func bootNodeRestartFlag(config *DeployConfig) string {
	if !config.BootNode {
		return ""
	}
	return " --restart " + bootNodeRestartPolicy
}

// bootNodeVolumeFlag mounts a boot node's firmware cache from the host so
// it outlives the container; empty outside boot-node mode.
func bootNodeVolumeFlag(config *DeployConfig) string {
	if !config.BootNode {
		return ""
	}
	return " -v " + shellQuote(config.FirmwareCacheDir) + ":" + ContainerFirmwareCacheDir
}

// bootstrapEnvFlags renders the -e VAR=val arguments for every set
// Bootstrap* field on the DeployConfig. Empty fields are skipped so
// the container's entrypoint defaults take effect, matching the
// "override only what's needed" deploy contract.
// portEnvValue renders a port for the container environment. Zero
// yields "" so the pair is skipped entirely and the entrypoint's own
// default takes effect — the same "empty means don't set it" contract
// every other bootstrap env flag follows.
func portEnvValue(port int) string {
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}

// boolEnvValue is "true" for true and empty (the entrypoint default,
// false) otherwise.
func boolEnvValue(v bool) string {
	if v {
		return "true"
	}
	return ""
}

func bootstrapEnvFlags(config *DeployConfig) string {
	pairs := []struct {
		name, value string
	}{
		{"BOOTSTRAP_INTERFACE", config.BootstrapInterface},
		{"BOOTSTRAP_BIND_HOST", config.BootstrapBindHost},
		{"BOOTSTRAP_SERVER_IP", config.BootstrapServerIP},
		{"BOOTSTRAP_HTTP_PORT", portEnvValue(config.BootstrapHTTPPort)},
		{"BOOTSTRAP_DEVICE_SCRIPT_PORT", portEnvValue(config.BootstrapDeviceScriptPort)},
		{"BOOTSTRAP_DHCP_START", config.BootstrapDHCPStart},
		{"BOOTSTRAP_DHCP_END", config.BootstrapDHCPEnd},
		{"BOOTSTRAP_GATEWAY", config.BootstrapGateway},
		{"BOOTSTRAP_NO_ROUTER", boolEnvValue(config.BootstrapNoRouter)},
		{"BOOTSTRAP_DNS", config.BootstrapDNS},
		{"BOOTSTRAP_APK_MIRROR", config.BootstrapAPKMirror},
		{"BOOTSTRAP_TFTP_DIR", config.netboot.tftpDir},
		{"BOOTSTRAP_ARM64_IPXE", config.netboot.arm64IPXE},
		{"BOOTSTRAP_PROXY_DHCP", boolEnvValue(config.BootstrapProxyDHCP)},
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
// Honours ContainerName + DataDir + ContainerImage from the config.
//
// The bootstrap container runs as root and writes root-owned files
// (install logs, registration JSON, per-MAC config bundles) into the
// bind-mounted DataDir. A non-root SSH user therefore cannot remove
// them with a plain host-side `rm -rf` — the previous implementation
// failed teardown with "Permission denied" on every container-written
// file and left stale state between runs.
//
// To delete root-owned files over SSH without sudo (which would prompt),
// we run the removal inside a throwaway root container of the bootstrap
// image, mounting the DataDir's parent so the leaf — including its
// mountpoint — is removed cleanly. The bootstrap container is removed
// first so its bind mount is released before the cleanup container runs.
//
// When no image is configured (teardown-only invocations that never
// supplied container_image) a root cleanup container cannot be started,
// so the command degrades to the host-side removal that works for the
// deployer-owned portions of the tree.
func GenerateTeardownCommand(config *DeployConfig) string {
	rt := shellQuote(config.ContainerRuntime)
	removeContainer := fmt.Sprintf("%s rm -f %s", rt, shellQuote(config.ContainerName))

	dataDir := strings.TrimRight(config.DataDir, "/")
	base := filepath.Base(dataDir)
	parent := filepath.Dir(dataDir)

	// Guard against an empty image (no root container available) and
	// pathological DataDir values that would target a parent directory
	// or the filesystem root.
	if config.ContainerImage == "" || base == "" || base == "." || base == ".." || base == "/" {
		return fmt.Sprintf("%s && rm -rf %s", removeContainer, shellQuote(config.DataDir))
	}

	cleanData := fmt.Sprintf(
		"%s run --rm -v %s:/host %s rm -rf %s",
		rt,
		shellQuote(parent),
		shellQuote(config.ContainerImage),
		shellQuote("/host/"+base),
	)
	return fmt.Sprintf("%s ; %s", removeContainer, cleanData)
}
