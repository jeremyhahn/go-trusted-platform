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

func TestIsMissingAssetError(t *testing.T) {
	missing := []string{
		"Error response from daemon: Could not find the file /data/vmlinuz in container",
		"Error: No such file or directory",
		"error: stat /data/foo: no such file",
		"Error: path /data/x does not exist in container abc",
	}
	for _, s := range missing {
		if !isMissingAssetError(s) {
			t.Errorf("expected missing-asset signal in %q", s)
		}
	}
	notMissing := []string{
		"docker: connection refused",
		"runtime crashed",
		"",
	}
	for _, s := range notMissing {
		if isMissingAssetError(s) {
			t.Errorf("did not expect missing-asset signal in %q", s)
		}
	}
}

func TestParseVerifyInspect(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantRunning string
		wantTag     string
		wantID      string
		wantBind    string
		wantOK      bool
	}{
		{
			name:        "four fields ok",
			output:      "true\tplatform-pxeboot:latest\tsha256:abc123\t/tmp/bootstrap",
			wantRunning: "true",
			wantTag:     "platform-pxeboot:latest",
			wantID:      "sha256:abc123",
			wantBind:    "/tmp/bootstrap",
			wantOK:      true,
		},
		{
			name:        "empty bind still four fields",
			output:      "true\timg:v1\tsha256:def\t",
			wantRunning: "true",
			wantTag:     "img:v1",
			wantID:      "sha256:def",
			wantBind:    "",
			wantOK:      true,
		},
		{
			name:        "leading and trailing whitespace trimmed",
			output:      "  true\timg:v1\tsha256:xyz\t/tmp/bootstrap  \n",
			wantRunning: "true",
			wantTag:     "img:v1",
			wantID:      "sha256:xyz",
			wantBind:    "/tmp/bootstrap",
			wantOK:      true,
		},
		{
			name:   "three fields not ok",
			output: "true\timg:v1\tsha256:abc",
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
			running, tag, id, bind, ok := parseVerifyInspect(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if running != tt.wantRunning {
				t.Errorf("running = %q, want %q", running, tt.wantRunning)
			}
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
			if id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
			if bind != tt.wantBind {
				t.Errorf("bind = %q, want %q", bind, tt.wantBind)
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
	got := bootstrapEnvFlags(&DeployConfig{BootstrapServerIP: "198.18.1.91"})

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
		BootstrapServerIP:         "198.18.1.91",
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
