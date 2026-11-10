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
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFake is the cause every scripted failure in this file carries.
type errFake struct{ what string }

func (e errFake) Error() string { return "fake: " + e.what }

// sessionRule answers every Run whose command contains match.
type sessionRule struct {
	match  string
	stdout string
	stderr string
	err    error
}

// fakeSession is an in-memory session.Session: Run answers from the first
// matching rule (an empty success otherwise) and Upload drains the reader.
type fakeSession struct {
	rules      []sessionRule
	uploadFail string
	closeErr   error

	runs    []string
	uploads []string
	closed  bool
	key     interface{ Destroy() }
}

func (s *fakeSession) Run(_ context.Context, cmd string) ([]byte, []byte, error) {
	s.runs = append(s.runs, cmd)
	for _, r := range s.rules {
		if strings.Contains(cmd, r.match) {
			return []byte(r.stdout), []byte(r.stderr), r.err
		}
	}
	return nil, nil, nil
}

func (s *fakeSession) Shell(context.Context) error { return nil }

func (s *fakeSession) Upload(_ context.Context, src io.Reader, remotePath string, _ fs.FileMode) error {
	if _, err := io.Copy(io.Discard, src); err != nil {
		return err
	}
	if s.uploadFail != "" && strings.Contains(remotePath, s.uploadFail) {
		return errFake{what: "upload " + remotePath}
	}
	s.uploads = append(s.uploads, remotePath)
	return nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	if s.key != nil {
		s.key.Destroy()
	}
	return s.closeErr
}

func (s *fakeSession) ran(substr string) bool {
	for _, cmd := range s.runs {
		if strings.Contains(cmd, substr) {
			return true
		}
	}
	return false
}

// useFakeDial routes session.Dial to s (or to dialErr) for one test.
func useFakeDial(t *testing.T, s *fakeSession, dialErr error) {
	t.Helper()
	orig := session.Dial
	session.Dial = func(_ context.Context, req session.DialRequest) (session.Session, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		s.key = req.Key
		return s, nil
	}
	t.Cleanup(func() { session.Dial = orig })
}

// scriptedLocal is the orchestrator-host runner: image inspect answers id,
// save answers saveErr.
type scriptedLocal struct {
	id      string
	saveErr error
	saved   bool
}

func (l *scriptedLocal) run(_ context.Context, _ string, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "save" {
		l.saved = true
		return "", l.saveErr
	}
	if l.id == "" {
		return "", errFake{what: "no local image"}
	}
	return l.id + "\n", nil
}

// deployFixture is a valid config whose key, manifest and netboot build exist.
func deployFixture(t *testing.T) *DeployConfig {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	generateTestKey(t, keyPath)
	manifest := filepath.Join(dir, "manifest.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("devices: []\n"), 0o600))
	return &DeployConfig{
		Host:            "198.51.100.7",
		User:            "root",
		SSHKeyPath:      keyPath,
		KnownHostsPath:  filepath.Join(dir, "known_hosts"),
		ContainerImage:  "pxeboot:test",
		ManifestPath:    manifest,
		NetbootMediaDir: piBuild(t, "kernel v1"),
	}
}

func newTestDeployer(local *scriptedLocal) *LinuxDeployer {
	d := NewLinuxDeployer(discard())
	d.local = local
	return d
}

// connectedClient is an SSHClient connected through the fake dial.
func connectedClient(t *testing.T, s *fakeSession) *SSHClient {
	t.Helper()
	useFakeDial(t, s, nil)
	cfg := deployFixture(t)
	client, err := NewSSHClient(cfg.Host, 0, cfg.User, cfg.SSHKeyPath, cfg.KnownHostsPath)
	require.NoError(t, err)
	require.NoError(t, client.Connect(t.Context()))
	require.True(t, client.IsConnected())
	return client
}

func TestDeploy_ShipsAChangedLocalImage(t *testing.T) {
	s := &fakeSession{rules: []sessionRule{
		{match: "image inspect --format", stdout: "sha256:old\n"},
		{match: " run -d ", stdout: "cid-1\n"},
	}}
	useFakeDial(t, s, nil)
	local := &scriptedLocal{id: "sha256:new"}

	res, err := newTestDeployer(local).Deploy(t.Context(), deployFixture(t))
	require.NoError(t, err)
	assert.Equal(t, &DeployResult{ContainerID: "cid-1", Host: "198.51.100.7", Running: true}, res)
	assert.True(t, local.saved, "the local image is saved for shipping")
	assert.Contains(t, s.uploads, remoteImageTar)
	assert.True(t, s.ran(GenerateImageLoadCommand(DefaultContainerRuntime, remoteImageTar)))
	assert.True(t, s.ran("rm -f "+shellQuote(remoteImageTar)), "the remote tar is cleaned up")
	assert.True(t, s.ran("| base64 -d > "+DefaultRemoteDataDir+"/manifest.yaml"), "the manifest is copied")
	assert.True(t, s.closed, "Deploy closes its session")
}

func TestDeploy_SkipsTheShipWhenTheRemoteImageMatches(t *testing.T) {
	s := &fakeSession{rules: []sessionRule{{match: "image inspect --format", stdout: "sha256:same\n"}}}
	useFakeDial(t, s, nil)
	local := &scriptedLocal{id: "sha256:same"}

	_, err := newTestDeployer(local).Deploy(t.Context(), deployFixture(t))
	require.NoError(t, err)
	assert.False(t, local.saved)
	assert.NotContains(t, s.uploads, remoteImageTar)
	assert.False(t, s.ran(" load -i "))
}

func TestDeploy_RegistryImage(t *testing.T) {
	tests := []struct {
		name     string
		rules    []sessionRule
		wantPull bool
		wantErr  bool
	}{
		{name: "present on the remote", wantPull: false},
		{
			name:     "absent is pulled",
			rules:    []sessionRule{{match: " image inspect 'pxeboot:test' >/dev/null", err: errFake{what: "absent"}}},
			wantPull: true,
		},
		{
			name: "pull failure surfaces",
			rules: []sessionRule{
				{match: " image inspect 'pxeboot:test' >/dev/null", err: errFake{what: "absent"}},
				{match: " pull ", stderr: "denied", err: errFake{what: "pull"}},
			},
			wantPull: true,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &fakeSession{rules: tt.rules}
			useFakeDial(t, s, nil)
			_, err := newTestDeployer(&scriptedLocal{}).Deploy(t.Context(), deployFixture(t))
			assert.Equal(t, tt.wantPull, s.ran(" pull 'pxeboot:test'"))
			if tt.wantErr {
				var cmdErr ErrSSHCommand
				require.ErrorAs(t, err, &cmdErr)
				assert.Equal(t, "denied", cmdErr.Output)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeploy_ImageShipFailures(t *testing.T) {
	tests := []struct {
		name      string
		saveErr   error
		session   *fakeSession
		wantPhase string
	}{
		{name: "save", saveErr: errFake{what: "save"}, session: &fakeSession{}, wantPhase: "save"},
		{name: "copy", session: &fakeSession{uploadFail: remoteImageTar}, wantPhase: "copy"},
		{
			name:      "load",
			session:   &fakeSession{rules: []sessionRule{{match: " load -i ", err: errFake{what: "load"}}}},
			wantPhase: "load",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeDial(t, tt.session, nil)
			local := &scriptedLocal{id: "sha256:new", saveErr: tt.saveErr}
			_, err := newTestDeployer(local).Deploy(t.Context(), deployFixture(t))
			var shipErr ErrImageShipFailed
			require.ErrorAs(t, err, &shipErr)
			assert.Equal(t, tt.wantPhase, shipErr.Phase)
			assert.False(t, tt.session.ran(" run -d "), "no container starts after a failed ship")
		})
	}
}

func TestDeploy_Failures(t *testing.T) {
	fail := func(match string) []sessionRule {
		return []sessionRule{{match: match, err: errFake{what: match}}}
	}
	tests := []struct {
		name    string
		mutate  func(*DeployConfig)
		rules   []sessionRule
		dialErr error
		target  any
	}{
		{name: "invalid config", mutate: func(c *DeployConfig) { c.Host = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "no known hosts", mutate: func(c *DeployConfig) { c.KnownHostsPath = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "unreadable key", mutate: func(c *DeployConfig) { c.SSHKeyPath = filepath.Join(t.TempDir(), "missing") }, target: &ErrSSHKeyRead{}},
		{name: "dial", dialErr: errFake{what: "dial"}, target: &ErrSSHConnect{}},
		{name: "prepare", rules: fail("mkdir -p '" + DefaultRemoteDataDir + "/configs'"), target: &ErrSSHCommand{}},
		{name: "manifest unreadable", mutate: func(c *DeployConfig) { c.ManifestPath = filepath.Join(t.TempDir(), "missing") }, target: &ErrFileRead{}},
		{name: "manifest copy", rules: fail("| base64 -d > "), target: &ErrFileCopy{}},
		{name: "netboot media", rules: fail("rm -rf "), target: &ErrNetbootMediaStage{}},
		{name: "container run", rules: fail(" run -d "), target: &ErrSSHCommand{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeDial(t, &fakeSession{rules: tt.rules}, tt.dialErr)
			cfg := deployFixture(t)
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			res, err := newTestDeployer(&scriptedLocal{}).Deploy(t.Context(), cfg)
			assert.Nil(t, res)
			require.ErrorAs(t, err, tt.target)
		})
	}
}

func TestDeploy_ReplaceFailureIsNotFatal(t *testing.T) {
	s := &fakeSession{rules: []sessionRule{
		{match: " rm -f 'pxeboot-bootstrap'", err: errFake{what: "rm"}},
		{match: " run -d ", stdout: "cid-2"},
	}}
	useFakeDial(t, s, nil)
	cfg := deployFixture(t)
	cfg.ContainerName = "pxeboot-bootstrap"

	res, err := newTestDeployer(&scriptedLocal{}).Deploy(t.Context(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "cid-2", res.ContainerID)
	assert.True(t, s.ran(" rm -f 'pxeboot-bootstrap'"))
}

func TestVerify(t *testing.T) {
	running := "true\tpxeboot:test\tsha256:abc\t" + DefaultRemoteDataDir + "\tno\t\n"
	tests := []struct {
		name      string
		mutate    func(*DeployConfig)
		inspect   sessionRule
		localID   string
		dialErr   error
		wantField string
		target    any
	}{
		{name: "running and current", inspect: sessionRule{stdout: running}, localID: "sha256:abc"},
		{name: "registry image without a local copy", inspect: sessionRule{stdout: running}},
		{name: "inspect fails", inspect: sessionRule{err: errFake{what: "inspect"}}, target: &ErrContainerNotRunning{}},
		{name: "unparseable inspect", inspect: sessionRule{stdout: "true\n"}, target: &ErrContainerNotRunning{}},
		{
			name:      "wrong image",
			inspect:   sessionRule{stdout: strings.Replace(running, "pxeboot:test", "pxeboot:old", 1)},
			wantField: "image",
		},
		{name: "stale digest", inspect: sessionRule{stdout: running}, localID: "sha256:new", wantField: "image-digest"},
		{name: "invalid config", mutate: func(c *DeployConfig) { c.ManifestPath = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "no known hosts", mutate: func(c *DeployConfig) { c.KnownHostsPath = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "dial", dialErr: errFake{what: "dial"}, target: &ErrSSHConnect{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.inspect
			rule.match = " inspect --format "
			s := &fakeSession{rules: []sessionRule{rule}}
			useFakeDial(t, s, tt.dialErr)
			cfg := deployFixture(t)
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			err := newTestDeployer(&scriptedLocal{id: tt.localID}).Verify(t.Context(), cfg)
			switch {
			case tt.wantField != "":
				var mismatch ErrContainerStateMismatch
				require.ErrorAs(t, err, &mismatch)
				assert.Equal(t, tt.wantField, mismatch.Field)
			case tt.target != nil:
				require.ErrorAs(t, err, tt.target)
			default:
				require.NoError(t, err)
				assert.True(t, s.closed)
			}
		})
	}
}

func TestTeardown(t *testing.T) {
	t.Run("runs the teardown command", func(t *testing.T) {
		s := &fakeSession{}
		useFakeDial(t, s, nil)
		cfg := deployFixture(t)
		require.NoError(t, NewLinuxDeployer(nil).Teardown(t.Context(), cfg))
		require.Len(t, s.runs, 1)
		assert.Equal(t, GenerateTeardownCommand(cfg), s.runs[0])
		assert.True(t, s.closed)
	})
	t.Run("a failing teardown command is not fatal", func(t *testing.T) {
		useFakeDial(t, &fakeSession{rules: []sessionRule{{match: "", err: errFake{what: "teardown"}}}}, nil)
		require.NoError(t, NewLinuxDeployer(nil).Teardown(t.Context(), deployFixture(t)))
	})

	failures := []struct {
		name    string
		mutate  func(*DeployConfig)
		dialErr error
		target  any
	}{
		{name: "invalid config", mutate: func(c *DeployConfig) { c.User = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "no known hosts", mutate: func(c *DeployConfig) { c.KnownHostsPath = "" }, target: &ErrInvalidDeployConfig{}},
		{name: "dial", dialErr: errFake{what: "dial"}, target: &ErrSSHConnect{}},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			s := &fakeSession{}
			useFakeDial(t, s, tt.dialErr)
			cfg := deployFixture(t)
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			require.ErrorAs(t, NewLinuxDeployer(nil).Teardown(t.Context(), cfg), tt.target)
			assert.Empty(t, s.runs)
		})
	}
}

func TestSSHClient_RunOutput(t *testing.T) {
	cause := errFake{what: "exit 1"}
	s := &fakeSession{rules: []sessionRule{
		{match: "ok", stdout: "out"},
		{match: "stderr", stdout: "out", stderr: "err", err: cause},
		{match: "stdout", stdout: "out", err: cause},
	}}
	client := connectedClient(t, s)

	out, err := client.Run(t.Context(), "ok")
	require.NoError(t, err)
	assert.Equal(t, "out", out)

	out, err = client.Run(t.Context(), "stderr")
	assert.Equal(t, "err", out, "stderr is preferred on failure")
	var cmdErr ErrSSHCommand
	require.ErrorAs(t, err, &cmdErr)
	assert.ErrorIs(t, err, cause)

	out, err = client.Run(t.Context(), "stdout")
	assert.Equal(t, "out", out, "stdout is the fallback without stderr")
	require.ErrorAs(t, err, &cmdErr)
}

func TestSSHClient_CopyFile(t *testing.T) {
	s := &fakeSession{}
	client := connectedClient(t, s)
	payload := []byte("binary\x00'payload'\n")
	local := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(local, payload, 0o600))

	require.NoError(t, client.CopyFile(t.Context(), local, "/remote/blob"))
	require.Len(t, s.runs, 1)
	encoded, ok := strings.CutPrefix(s.runs[0], "echo '")
	require.True(t, ok)
	encoded, ok = strings.CutSuffix(encoded, "' | base64 -d > /remote/blob")
	require.True(t, ok)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, payload, decoded)

	var readErr ErrFileRead
	require.ErrorAs(t, client.CopyFile(t.Context(), filepath.Join(t.TempDir(), "missing"), "/r"), &readErr)
}

func TestSSHClient_CopyFileStream(t *testing.T) {
	s := &fakeSession{uploadFail: "/fail"}
	client := connectedClient(t, s)
	local := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(local, []byte("tar"), 0o600))

	require.NoError(t, client.CopyFileStream(t.Context(), local, "/remote/image.tar"))
	assert.Equal(t, []string{"/remote/image.tar"}, s.uploads)

	var copyErr ErrFileCopy
	require.ErrorAs(t, client.CopyFileStream(t.Context(), local, "/fail"), &copyErr)
	assert.Equal(t, "/fail", copyErr.Remote)

	var readErr ErrFileRead
	require.ErrorAs(t, client.CopyFileStream(t.Context(), filepath.Join(t.TempDir(), "missing"), "/r"), &readErr)
}

func TestSSHClient_StatRemote(t *testing.T) {
	tests := []struct {
		name      string
		rule      sessionRule
		wantSize  int64
		wantMtime int64
		target    any
	}{
		{name: "size and mtime", rule: sessionRule{stdout: "123 456\n"}, wantSize: 123, wantMtime: 456},
		{name: "missing", rule: sessionRule{stdout: "MISSING\n"}, target: &ErrRemoteFileNotFound{}},
		{name: "empty", rule: sessionRule{}, target: &ErrRemoteFileNotFound{}},
		{name: "wrong field count", rule: sessionRule{stdout: "1 2 3"}, target: &ErrUnexpectedStatOutput{}},
		{name: "bad size", rule: sessionRule{stdout: "x 2"}, target: &ErrFileRead{}},
		{name: "bad mtime", rule: sessionRule{stdout: "1 y"}, target: &ErrFileRead{}},
		{name: "run fails", rule: sessionRule{err: errFake{what: "stat"}}, target: &ErrSSHCommand{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule
			rule.match = "stat -c"
			client := connectedClient(t, &fakeSession{rules: []sessionRule{rule}})
			size, mtime, err := client.StatRemote(t.Context(), "/data/file")
			if tt.target != nil {
				require.ErrorAs(t, err, tt.target)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, size)
			assert.Equal(t, tt.wantMtime, mtime)
		})
	}

	notConnected, err := NewSSHClient("h", 22, "u", "/k", "/kh")
	require.NoError(t, err)
	_, _, err = notConnected.StatRemote(t.Context(), "/data/file")
	var nc ErrSSHNotConnected
	require.ErrorAs(t, err, &nc)
}

func TestSSHClient_CloseReturnsTheSessionErrorOnce(t *testing.T) {
	closeErr := errFake{what: "close"}
	s := &fakeSession{closeErr: closeErr}
	client := connectedClient(t, s)

	require.ErrorIs(t, client.Close(), closeErr)
	assert.True(t, s.closed)
	assert.False(t, client.IsConnected())
	require.NoError(t, client.Close(), "a second Close is a no-op")
	_, err := client.Run(t.Context(), "true")
	var nc ErrSSHNotConnected
	require.ErrorAs(t, err, &nc)
}

func TestErrorMessagesAndCauses(t *testing.T) {
	cause := errFake{what: "cause"}
	tests := []struct {
		err   error
		parts []string
		wraps bool
	}{
		{ErrSSHConnect{Host: "h", Port: 2222, Cause: cause}, []string{"h:2222", "fake: cause"}, true},
		{ErrSSHCommand{Command: "ls", Output: "boom", Cause: cause}, []string{`"ls"`, "boom"}, true},
		{ErrSSHKeyRead{Path: "/k", Cause: cause}, []string{"read SSH key /k"}, true},
		{ErrSSHKeyParse{Path: "/k", Cause: cause}, []string{"parse SSH key /k"}, true},
		{ErrFileCopy{Local: "/l", Remote: "/r", Cause: cause}, []string{"copy /l to /r"}, true},
		{ErrFileRead{Path: "/p", Cause: cause}, []string{"local file /p"}, true},
		{ErrNetbootMediaStage{Step: "uploading x", Err: cause}, []string{"netboot media: uploading x: fake: cause"}, true},
		{ErrRemoteFileNotFound{Path: "/p"}, []string{"not found: /p"}, false},
		{ErrUnexpectedStatOutput{Output: "1 2 3"}, []string{`"1 2 3"`}, false},
		{ErrContainerNotRunning{ContainerID: "c", Host: "h"}, []string{"container c on h is not running"}, false},
		{ErrContainerStateMismatch{ContainerID: "c", Host: "h", Field: "image", Want: "a", Got: "b"}, []string{"image", `want="a"`, `got="b"`}, false},
		{ErrInvalidDeployConfig{Field: "host", Reason: "must not be empty"}, []string{"field host: must not be empty"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.parts[0], func(t *testing.T) {
			msg := tt.err.Error()
			assert.True(t, strings.HasPrefix(msg, "deployer: "), msg)
			for _, p := range tt.parts {
				assert.Contains(t, msg, p)
			}
			assert.Equal(t, tt.wraps, errors.Is(tt.err, cause))
		})
	}
}
