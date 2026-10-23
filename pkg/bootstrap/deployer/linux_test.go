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
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// All commands run remotely over SSH so every interpolated value is
// shell-quoted (single quotes). Tests verify the unquoted prefix and
// the quoted occurrences so the substring assertions remain stable
// against safer-quoting refactors.

func TestLinuxDeployer_GenerateRunCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "ghcr.io/org/bootstrap:latest",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)

	if !strings.HasPrefix(cmd, "'docker' run -d --name") {
		t.Errorf("expected command to start with quoted 'docker' run -d, got: %s", cmd)
	}
	if !strings.Contains(cmd, "'"+DefaultContainerName+"'") {
		t.Errorf("expected quoted container name %q in command, got: %s", DefaultContainerName, cmd)
	}
	if !strings.Contains(cmd, "--net=host") {
		t.Error("expected '--net=host' in command")
	}
	if !strings.Contains(cmd, "'"+DefaultRemoteDataDir+"':/data") {
		t.Errorf("expected quoted volume mount %q:/data in command, got: %s", DefaultRemoteDataDir, cmd)
	}
	if !strings.Contains(cmd, "'"+config.ContainerImage+"'") {
		t.Errorf("expected quoted container image in command, got: %s", cmd)
	}
}

func TestLinuxDeployer_GenerateRunCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
		ContainerImage:   "ghcr.io/org/bootstrap:v1.0",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)

	if !strings.HasPrefix(cmd, "'podman' run -d") {
		t.Errorf("expected command to start with 'podman' run -d, got: %s", cmd)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)

	if !strings.Contains(cmd, "'docker' rm -f '"+DefaultContainerName+"'") {
		t.Errorf("expected quoted 'docker' rm -f with container name in command, got: %s", cmd)
	}
	if !strings.Contains(cmd, "rm -rf '"+DefaultRemoteDataDir+"'") {
		t.Errorf("expected 'rm -rf %q' in command, got: %s", DefaultRemoteDataDir, cmd)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand_Podman(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "podman",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)

	if !strings.HasPrefix(cmd, "'podman' rm -f") {
		t.Errorf("expected command to start with 'podman' rm -f, got: %s", cmd)
	}
}

func TestLinuxDeployer_DataDirOverride(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "img:v1",
		DataDir:          "/var/lib/trusted-bootstrap",
	}
	config.ApplyDefaults()

	cmd := GenerateRunCommand(config)
	if !strings.Contains(cmd, "'/var/lib/trusted-bootstrap':/data") {
		t.Errorf("expected DataDir override honoured, got: %s", cmd)
	}

	teardown := GenerateTeardownCommand(config)
	// With an image configured the data dir is removed by a root cleanup
	// container that mounts the DataDir's parent and removes the leaf.
	if !strings.Contains(teardown, "-v '/var/lib':/host 'img:v1' rm -rf '/host/trusted-bootstrap'") {
		t.Errorf("expected root cleanup container honouring DataDir, got: %s", teardown)
	}
	if !strings.Contains(teardown, "'docker' rm -f '"+DefaultContainerName+"'") {
		t.Errorf("expected container removal in teardown, got: %s", teardown)
	}
}

// TestGenerateRunCommand_BootNode: boot-node mode adds the restart policy
// and the firmware cache volume; default mode carries neither.
func TestGenerateRunCommand_BootNode(t *testing.T) {
	const restartFlag = "--restart unless-stopped"
	firmwareVolume := "-v '/srv/pxeboot-firmware':" + ContainerFirmwareCacheDir + " "

	bootNode := &DeployConfig{ContainerImage: "platform-pxeboot:latest", DataDir: "/srv/pxeboot", BootNode: true}
	bootNode.ApplyDefaults()
	cmd := GenerateRunCommand(bootNode)
	for _, want := range []string{restartFlag, firmwareVolume, "-v '/srv/pxeboot':/data "} {
		if !strings.Contains(cmd, want) {
			t.Errorf("boot-node run command missing %q: %s", want, cmd)
		}
	}

	defaultMode := &DeployConfig{ContainerImage: "platform-pxeboot:latest", DataDir: "/srv/pxeboot"}
	defaultMode.ApplyDefaults()
	cmd = GenerateRunCommand(defaultMode)
	for _, unwanted := range []string{"--restart", ContainerFirmwareCacheDir} {
		if strings.Contains(cmd, unwanted) {
			t.Errorf("default-mode run command carries %q: %s", unwanted, cmd)
		}
	}
}

// TestGeneratePrepareCommand: Deploy creates the host directories the
// container mounts; podman refuses a missing bind source, so boot-node
// mode creates the firmware cache too.
func TestGeneratePrepareCommand(t *testing.T) {
	bootNode := &DeployConfig{DataDir: "/srv/pxeboot", BootNode: true}
	bootNode.ApplyDefaults()
	if got, want := GeneratePrepareCommand(bootNode), "mkdir -p '/srv/pxeboot/configs' '/srv/pxeboot-firmware'"; got != want {
		t.Errorf("boot-node prepare = %q, want %q", got, want)
	}

	defaultMode := &DeployConfig{}
	defaultMode.ApplyDefaults()
	if got, want := GeneratePrepareCommand(defaultMode), "mkdir -p '"+DefaultRemoteDataDir+"/configs'"; got != want {
		t.Errorf("default prepare = %q, want %q", got, want)
	}
}

// TestRedeploy_KeepsBootNodeVolumes: a re-run replaces the container and
// keeps both host volumes. The replace step removes only the named
// container, the prepare step only creates directories, and the new
// container mounts the same host paths as the old one.
func TestRedeploy_KeepsBootNodeVolumes(t *testing.T) {
	first := &DeployConfig{ContainerImage: "platform-pxeboot:latest", DataDir: "/srv/pxeboot", BootNode: true}
	first.ApplyDefaults()
	second := &DeployConfig{ContainerImage: "platform-pxeboot:v2", DataDir: "/srv/pxeboot", BootNode: true}
	second.ApplyDefaults()

	replace := GenerateReplaceCommand(second)
	if want := "'docker' rm -f '" + DefaultContainerName + "' 2>/dev/null || true"; replace != want {
		t.Errorf("replace = %q, want %q", replace, want)
	}
	for _, cmd := range []string{replace, GeneratePrepareCommand(second)} {
		if strings.Contains(cmd, "rm -rf") || strings.Contains(cmd, " -v") {
			t.Errorf("re-deploy step touches a volume: %s", cmd)
		}
	}

	for _, mount := range []string{"-v '/srv/pxeboot':/data ", "-v '/srv/pxeboot-firmware':" + ContainerFirmwareCacheDir + " "} {
		if !strings.Contains(GenerateRunCommand(first), mount) || !strings.Contains(GenerateRunCommand(second), mount) {
			t.Errorf("both deploys must mount %q", mount)
		}
	}
}

// TestGenerateTeardownCommand_BootNodeKeepsFirmwareCache: an explicit
// teardown removes the container and data_dir as in default mode; the
// firmware cache beside data_dir is left on the host.
func TestGenerateTeardownCommand_BootNodeKeepsFirmwareCache(t *testing.T) {
	config := &DeployConfig{ContainerImage: "platform-pxeboot:latest", DataDir: "/srv/pxeboot", BootNode: true}
	config.ApplyDefaults()
	cmd := GenerateTeardownCommand(config)
	if !strings.Contains(cmd, "'docker' rm -f '"+DefaultContainerName+"'") {
		t.Errorf("teardown must remove the container: %s", cmd)
	}
	if !strings.Contains(cmd, "rm -rf '/host/pxeboot'") {
		t.Errorf("teardown must remove data_dir: %s", cmd)
	}
	if strings.Contains(cmd, "firmware") {
		t.Errorf("teardown must keep the firmware cache: %s", cmd)
	}
}

// TestImageFirmwareDirMatchesMount: the bootstrap image must point pxeboot
// at the directory boot-node mode mounts from the host. Left to its own
// default, pxeboot running as root caches under ~/.cache, and the mounted
// cache would stay empty while every restart downloads again.
func TestImageFirmwareDirMatchesMount(t *testing.T) {
	conf, err := os.ReadFile("../../../build/docker/bootstrap/supervisord.conf")
	if err != nil {
		t.Fatalf("read supervisord.conf: %v", err)
	}
	if want := "--firmware-dir " + ContainerFirmwareCacheDir + "\n"; !strings.Contains(string(conf), want) {
		t.Errorf("supervisord.conf pxeboot command lacks %q", want)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand_RootCleanupContainer(t *testing.T) {
	config := &DeployConfig{
		ContainerRuntime: "docker",
		ContainerImage:   "platform-pxeboot:latest",
		DataDir:          "/tmp/pxeboot-data",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)

	// Container must be removed before the cleanup container runs so its
	// bind mount is released.
	rmIdx := strings.Index(cmd, "rm -f")
	cleanIdx := strings.Index(cmd, "run --rm")
	if rmIdx == -1 || cleanIdx == -1 || rmIdx > cleanIdx {
		t.Fatalf("expected container removal before root cleanup container, got: %s", cmd)
	}
	// Cleanup mounts the parent and removes the leaf as root.
	if !strings.Contains(cmd, "-v '/tmp':/host 'platform-pxeboot:latest' rm -rf '/host/pxeboot-data'") {
		t.Errorf("expected parent-mount root cleanup of leaf dir, got: %s", cmd)
	}
	// A plain host-side rm of the root-owned dir must not be used when an
	// image is available.
	if strings.Contains(cmd, "&& rm -rf '/tmp/pxeboot-data'") {
		t.Errorf("expected no host-side rm of root-owned data dir, got: %s", cmd)
	}
}

func TestLinuxDeployer_GenerateTeardownCommand_NoImageHostRemoval(t *testing.T) {
	// Without an image we cannot run a root cleanup container; the command
	// degrades to a host-side removal.
	config := &DeployConfig{
		ContainerRuntime: "docker",
		DataDir:          "/tmp/pxeboot-data",
	}
	config.ApplyDefaults()

	cmd := GenerateTeardownCommand(config)
	if !strings.Contains(cmd, "&& rm -rf '/tmp/pxeboot-data'") {
		t.Errorf("expected host-side rm fallback when no image, got: %s", cmd)
	}
	if strings.Contains(cmd, "run --rm") {
		t.Errorf("expected no cleanup container without an image, got: %s", cmd)
	}
}

func TestDeployConfig_ApplyDefaults_DataDirAndContainerName(t *testing.T) {
	c := &DeployConfig{}
	c.ApplyDefaults()
	if c.DataDir != DefaultRemoteDataDir {
		t.Errorf("expected DataDir default %q, got %q", DefaultRemoteDataDir, c.DataDir)
	}
	if c.ContainerName != DefaultContainerName {
		t.Errorf("expected ContainerName default %q, got %q", DefaultContainerName, c.ContainerName)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":        "'plain'",
		"with space":   "'with space'",
		"with'quote":   `'with'\''quote'`,
		"":             "''",
		"a'b'c":        `'a'\''b'\''c'`,
		"--flag=value": "'--flag=value'",
	}
	for in, want := range cases {
		got := shellQuote(in)
		if got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVerifyInspect(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   inspectState
		wantOK bool
	}{
		{
			name:   "six fields ok",
			output: "true\tplatform-pxeboot:latest\tsha256:abc123\t/srv/pxeboot\tunless-stopped\t/srv/pxeboot-firmware",
			want: inspectState{
				Running:       "true",
				Image:         "platform-pxeboot:latest",
				ImageID:       "sha256:abc123",
				DataBind:      "/srv/pxeboot",
				RestartPolicy: "unless-stopped",
				FirmwareBind:  "/srv/pxeboot-firmware",
			},
			wantOK: true,
		},
		{
			name:   "default-mode container has empty trailing fields",
			output: "true\timg:v1\tsha256:def\t/tmp/bootstrap\tno\t",
			want: inspectState{
				Running:       "true",
				Image:         "img:v1",
				ImageID:       "sha256:def",
				DataBind:      "/tmp/bootstrap",
				RestartPolicy: "no",
			},
			wantOK: true,
		},
		{
			name:   "leading and trailing whitespace trimmed",
			output: "  true\timg:v1\tsha256:xyz\t/tmp/bootstrap\t\t  \n",
			want: inspectState{
				Running:  "true",
				Image:    "img:v1",
				ImageID:  "sha256:xyz",
				DataBind: "/tmp/bootstrap",
			},
			wantOK: true,
		},
		{
			name:   "four fields not ok",
			output: "true\timg:v1\tsha256:abc\t/tmp/bootstrap",
			wantOK: false,
		},
		{
			name:   "empty output not ok",
			output: "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseVerifyInspect(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("state = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestVerifyInspectFormat_FieldCount(t *testing.T) {
	if got := strings.Count(verifyInspectFormat, "\t") + 1; got != verifyInspectFields {
		t.Fatalf("verifyInspectFormat has %d fields, parser expects %d", got, verifyInspectFields)
	}
	if !strings.Contains(verifyInspectFormat, `eq .Destination "`+ContainerFirmwareCacheDir+`"`) {
		t.Errorf("verifyInspectFormat does not read the firmware cache mount: %s", verifyInspectFormat)
	}
}

func TestCheckContainerState(t *testing.T) {
	defaultMode := &DeployConfig{
		ContainerName:  "bootstrap-server",
		ContainerImage: "platform-pxeboot:latest",
		DataDir:        "/srv/pxeboot",
	}
	bootNode := &DeployConfig{
		ContainerName:    "bootstrap-server",
		ContainerImage:   "platform-pxeboot:latest",
		DataDir:          "/srv/pxeboot",
		BootNode:         true,
		FirmwareCacheDir: "/srv/pxeboot-firmware",
	}
	serving := inspectState{
		Running:       "true",
		Image:         "platform-pxeboot:latest",
		DataBind:      "/srv/pxeboot",
		RestartPolicy: "unless-stopped",
		FirmwareBind:  "/srv/pxeboot-firmware",
	}
	withField := func(mutate func(*inspectState)) inspectState {
		s := serving
		mutate(&s)
		return s
	}
	tests := []struct {
		name      string
		config    *DeployConfig
		got       inspectState
		wantField string // empty for a match, not-running for ErrContainerNotRunning
	}{
		{"boot node matches", bootNode, serving, ""},
		{"default mode ignores restart policy and cache", defaultMode,
			withField(func(s *inspectState) { s.RestartPolicy, s.FirmwareBind = "no", "" }), ""},
		{"stopped container", bootNode, withField(func(s *inspectState) { s.Running = "false" }), "not-running"},
		{"image differs", defaultMode, withField(func(s *inspectState) { s.Image = "other:v2" }), "image"},
		{"data bind differs", defaultMode, withField(func(s *inspectState) { s.DataBind = "/tmp/bootstrap" }), "bind-mount"},
		{"boot node without restart policy", bootNode,
			withField(func(s *inspectState) { s.RestartPolicy = "no" }), "restart-policy"},
		{"boot node without firmware cache", bootNode,
			withField(func(s *inspectState) { s.FirmwareBind = "" }), "firmware-cache"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkContainerState(tt.config, tt.got)
			switch tt.wantField {
			case "":
				if err != nil {
					t.Fatalf("checkContainerState = %v, want nil", err)
				}
			case "not-running":
				var notRunning ErrContainerNotRunning
				if !errors.As(err, &notRunning) {
					t.Fatalf("checkContainerState = %v, want ErrContainerNotRunning", err)
				}
			default:
				var mismatch ErrContainerStateMismatch
				if !errors.As(err, &mismatch) {
					t.Fatalf("checkContainerState = %v, want ErrContainerStateMismatch", err)
				}
				if mismatch.Field != tt.wantField {
					t.Errorf("mismatch field = %q, want %q", mismatch.Field, tt.wantField)
				}
			}
		})
	}
}

func TestImageStale(t *testing.T) {
	tests := []struct {
		name      string
		localID   string
		runningID string
		want      bool
	}{
		{name: "equal not stale", localID: "sha256:abc", runningID: "sha256:abc", want: false},
		{name: "differ stale", localID: "sha256:new", runningID: "sha256:old", want: true},
		{name: "empty local not stale", localID: "", runningID: "sha256:old", want: false},
		{name: "empty running not stale", localID: "sha256:new", runningID: "", want: false},
		{name: "both empty not stale", localID: "", runningID: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imageStale(tt.localID, tt.runningID); got != tt.want {
				t.Errorf("imageStale(%q, %q) = %v, want %v", tt.localID, tt.runningID, got, tt.want)
			}
		})
	}
}

func TestGenerateImageLoadCommand(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		tar     string
		want    string
	}{
		{
			name:    "docker",
			runtime: "docker",
			tar:     "/tmp/.pxeboot-image-load.tar",
			want:    "'docker' load -i '/tmp/.pxeboot-image-load.tar'",
		},
		{
			name:    "podman",
			runtime: "podman",
			tar:     "/tmp/.pxeboot-image-load.tar",
			want:    "'podman' load -i '/tmp/.pxeboot-image-load.tar'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateImageLoadCommand(tt.runtime, tt.tar); got != tt.want {
				t.Errorf("GenerateImageLoadCommand(%q, %q) = %q, want %q", tt.runtime, tt.tar, got, tt.want)
			}
		})
	}
}

func TestLocalImageInspectArgs(t *testing.T) {
	got := localImageInspectArgs("platform-pxeboot:latest")
	want := []string{"image", "inspect", "--format", "{{.Id}}", "platform-pxeboot:latest"}
	if len(got) != len(want) {
		t.Fatalf("localImageInspectArgs len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRemoteImageInspectCmd(t *testing.T) {
	got := remoteImageInspectCmd("docker", "platform-pxeboot:latest")
	want := "'docker' image inspect --format '{{.Id}}' 'platform-pxeboot:latest'"
	if got != want {
		t.Errorf("remoteImageInspectCmd = %q, want %q", got, want)
	}
}

// fakeLocalRunner is an injectable localRunner for unit tests. It records
// the last invocation and returns canned output/error.
type fakeLocalRunner struct {
	out      string
	err      error
	gotName  string
	gotArgs  []string
	callited bool
}

func (f *fakeLocalRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	f.callited = true
	f.gotName = name
	f.gotArgs = args
	return f.out, f.err
}

func TestLinuxDeployer_localImageID(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		err     error
		wantID  string
		wantCmd bool
	}{
		{
			name:    "success returns trimmed id",
			out:     "sha256:deadbeef\n",
			err:     nil,
			wantID:  "sha256:deadbeef",
			wantCmd: true,
		},
		{
			name:    "runner error yields empty id",
			out:     "no such image",
			err:     errors.New("exit status 1"),
			wantID:  "",
			wantCmd: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeLocalRunner{out: tt.out, err: tt.err}
			d := &LinuxDeployer{logger: slog.Default(), local: fake}

			id := d.localImageID(context.Background(), "docker", "platform-pxeboot:latest")
			if id != tt.wantID {
				t.Errorf("localImageID = %q, want %q", id, tt.wantID)
			}
			if fake.callited != tt.wantCmd {
				t.Errorf("runner called = %v, want %v", fake.callited, tt.wantCmd)
			}
			if fake.gotName != "docker" {
				t.Errorf("runner name = %q, want docker", fake.gotName)
			}
			wantArgs := localImageInspectArgs("platform-pxeboot:latest")
			if len(fake.gotArgs) != len(wantArgs) {
				t.Fatalf("runner args = %v, want %v", fake.gotArgs, wantArgs)
			}
			for i := range wantArgs {
				if fake.gotArgs[i] != wantArgs[i] {
					t.Errorf("runner arg[%d] = %q, want %q", i, fake.gotArgs[i], wantArgs[i])
				}
			}
		})
	}
}

func TestNewLinuxDeployer_LocalRunnerWired(t *testing.T) {
	d := NewLinuxDeployer(nil)
	if d.local == nil {
		t.Fatal("expected NewLinuxDeployer to wire a non-nil localRunner")
	}
	if _, ok := d.local.(execLocalRunner); !ok {
		t.Errorf("expected execLocalRunner, got %T", d.local)
	}
}

func TestErrImageShipFailed(t *testing.T) {
	cause := errors.New("boom")
	e := ErrImageShipFailed{Phase: "save", Cause: cause}
	if !strings.Contains(e.Error(), "save") {
		t.Errorf("expected phase in error string, got: %s", e.Error())
	}
	if !errors.Is(e, cause) {
		t.Errorf("expected Unwrap to expose cause")
	}

	// Nil cause must not panic and must still name the phase.
	e2 := ErrImageShipFailed{Phase: "load"}
	if !strings.Contains(e2.Error(), "load") {
		t.Errorf("expected phase in error string for nil-cause variant, got: %s", e2.Error())
	}
	if e2.Unwrap() != nil {
		t.Errorf("expected nil Unwrap for nil-cause variant")
	}
}

// TestBootstrapEnvFlags_PortsOmittedWhenZero keeps the "empty means
// don't set it" contract every other bootstrap env flag follows. A
// zero port must produce no -e pair at all, so the container
// entrypoint's own default takes effect rather than a bare `-e
// BOOTSTRAP_HTTP_PORT=0` pinning the server to port 0.
func TestBootstrapEnvFlags_PortsOmittedWhenZero(t *testing.T) {
	got := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "10.4.2.91"})

	for _, name := range []string{"BOOTSTRAP_HTTP_PORT", "BOOTSTRAP_DEVICE_SCRIPT_PORT"} {
		if strings.Contains(got, name) {
			t.Fatalf("env flags = %q, must not mention %s when the port is zero", got, name)
		}
	}
}

// TestBootstrapEnvFlags_PortsEmittedWhenSet is the plumbing half of the
// port fix: a configured port has to reach the container, or the
// bootstrap.yaml field is decorative.
func TestBootstrapEnvFlags_PortsEmittedWhenSet(t *testing.T) {
	got := bootstrapEnvFlags(&DeployConfig{
		BootstrapServerIP:         "10.4.2.91",
		BootstrapHTTPPort:         18080,
		BootstrapDeviceScriptPort: 18081,
	})

	// Values are shell-quoted by shellQuote, same as every other pair.
	for _, want := range []string{"-e BOOTSTRAP_HTTP_PORT='18080'", "-e BOOTSTRAP_DEVICE_SCRIPT_PORT='18081'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("env flags = %q, want it to contain %q", got, want)
		}
	}
}

// TestBootstrapEnvFlags_BindHost pins BOOTSTRAP_BIND_HOST (#93): the
// configured host reaches the container, and an unset one leaves the
// entrypoint's every-interface default alone.
func TestBootstrapEnvFlags_BindHost(t *testing.T) {
	unset := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "10.4.2.91"})
	if strings.Contains(unset, "BOOTSTRAP_BIND_HOST") {
		t.Fatalf("env flags = %q, must not mention BOOTSTRAP_BIND_HOST when unset", unset)
	}

	got := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "10.4.2.91", BootstrapBindHost: "10.4.2.91"})
	if want := "-e BOOTSTRAP_BIND_HOST='10.4.2.91'"; !strings.Contains(got, want) {
		t.Fatalf("env flags = %q, want it to contain %q", got, want)
	}
}

// TestGenerateRunCommand_CarriesPorts pins that the ports survive into
// the actual docker run command, not just the flag builder.
func TestGenerateRunCommand_CarriesPorts(t *testing.T) {
	cmd := GenerateRunCommand(&DeployConfig{
		Host:                      "deploy-host",
		BootstrapHTTPPort:         18080,
		BootstrapDeviceScriptPort: 18081,
	})

	if !strings.Contains(cmd, "BOOTSTRAP_DEVICE_SCRIPT_PORT='18081'") {
		t.Fatalf("run command does not carry the device-script port: %s", cmd)
	}
	if !strings.Contains(cmd, "BOOTSTRAP_HTTP_PORT='18080'") {
		t.Fatalf("run command does not carry the http port: %s", cmd)
	}
}

// TestPortEnvValue covers the renderer directly, including the zero
// case that the omission contract depends on.
func TestPortEnvValue(t *testing.T) {
	if got := portEnvValue(0); got != "" {
		t.Fatalf("portEnvValue(0) = %q, want \"\"", got)
	}
	if got := portEnvValue(8081); got != "8081" {
		t.Fatalf("portEnvValue(8081) = %q, want \"8081\"", got)
	}
}

// TestBootstrapEnvFlags_NoRouter: the no-router setting reaches the
// container as BOOTSTRAP_NO_ROUTER, and off it is not mentioned, so a
// configured gateway and the entrypoint default work as before.
func TestBootstrapEnvFlags_NoRouter(t *testing.T) {
	on := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "192.0.2.1", BootstrapNoRouter: true})
	if !strings.Contains(on, "-e BOOTSTRAP_NO_ROUTER='true'") {
		t.Fatalf("env flags = %q, want BOOTSTRAP_NO_ROUTER='true'", on)
	}
	if strings.Contains(on, "BOOTSTRAP_GATEWAY") {
		t.Fatalf("env flags = %q, must not pass a gateway with no-router", on)
	}

	off := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "192.0.2.1", BootstrapGateway: "192.0.2.254"})
	if strings.Contains(off, "BOOTSTRAP_NO_ROUTER") {
		t.Fatalf("env flags = %q, must not mention BOOTSTRAP_NO_ROUTER when off", off)
	}
	if !strings.Contains(off, "-e BOOTSTRAP_GATEWAY='192.0.2.254'") {
		t.Fatalf("env flags = %q, want the configured gateway", off)
	}
}

// TestBootstrapEnvFlags_Netboot pins that the staged build's TFTP tree and
// arm64 iPXE, and proxy DHCP, reach the container — and that nothing is
// said when they are not configured, so the entrypoint's defaults hold.
func TestBootstrapEnvFlags_Netboot(t *testing.T) {
	quiet := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "10.0.0.1"})
	for _, name := range []string{"BOOTSTRAP_TFTP_DIR", "BOOTSTRAP_ARM64_IPXE", "BOOTSTRAP_PROXY_DHCP"} {
		if strings.Contains(quiet, name) {
			t.Fatalf("env flags = %q, must not mention %s when unset", quiet, name)
		}
	}
	got := bootstrapEnvFlags(&DeployConfig{
		BootstrapServerIP:  "10.0.0.1",
		BootstrapProxyDHCP: true,
		netboot:            netbootMediaPaths{tftpDir: "/data/rpi-tftp", arm64IPXE: "/data/firmware/snponly-aarch64.efi"},
	})
	for _, want := range []string{"-e BOOTSTRAP_TFTP_DIR='/data/rpi-tftp'", "-e BOOTSTRAP_ARM64_IPXE='/data/firmware/snponly-aarch64.efi'", "-e BOOTSTRAP_PROXY_DHCP='true'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("env flags = %q, want it to contain %q", got, want)
		}
	}
}
