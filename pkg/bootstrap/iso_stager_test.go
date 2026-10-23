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

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// fakeRemoteISOClient is an in-memory remoteISOClient used by the
// iso_stager unit tests. It records every Run command, every
// CopyFileStream invocation, and the resulting "remote" file contents,
// so the freshness logic can be exercised without a real SSH server.
type fakeRemoteISOClient struct {
	// remoteFiles maps remote path to the bytes the fake "remote host"
	// holds. A missing entry means the file does not exist remotely.
	remoteFiles map[string][]byte

	// statErr, runErr, copyErr, connectErr, closeErr override the
	// corresponding return value when set, used to simulate
	// transport-layer failures.
	statErr    error
	runErr     error
	copyErr    error
	connectErr error
	closeErr   error

	// copyErrFor, when non-empty, only fails CopyFileStream calls whose
	// remotePath equals this value. Useful for failing only the sidecar
	// upload while letting the ISO upload succeed.
	copyErrFor string

	// Recorded events for assertions.
	connected bool
	closed    bool
	commands  []string
	uploaded  []string
}

func newFakeRemoteISOClient() *fakeRemoteISOClient {
	return &fakeRemoteISOClient{
		remoteFiles: make(map[string][]byte),
	}
}

func (f *fakeRemoteISOClient) Connect(ctx context.Context) error {
	f.connected = true
	return f.connectErr
}

func (f *fakeRemoteISOClient) Close() error {
	f.closed = true
	return f.closeErr
}

func (f *fakeRemoteISOClient) Run(ctx context.Context, command string) (string, error) {
	f.commands = append(f.commands, command)
	if f.runErr != nil {
		return "", f.runErr
	}
	// "cat '<path>' 2>/dev/null || echo MISSING" -- read sidecar.
	if strings.HasPrefix(command, "cat '") {
		// Extract path between the first "'" pair.
		body := strings.TrimPrefix(command, "cat '")
		end := strings.Index(body, "'")
		if end < 0 {
			return "", errFakeRemote{Op: "cat-parse", Path: command}
		}
		path := body[:end]
		data, ok := f.remoteFiles[path]
		if !ok {
			return "MISSING\n", nil
		}
		return string(data), nil
	}
	// mkdir, touch, etc. all silently succeed by default.
	return "", nil
}

func (f *fakeRemoteISOClient) StatRemote(ctx context.Context, remotePath string) (int64, int64, error) {
	if f.statErr != nil {
		return 0, 0, f.statErr
	}
	data, ok := f.remoteFiles[remotePath]
	if !ok {
		return 0, 0, deployer.ErrRemoteFileNotFound{Path: remotePath}
	}
	return int64(len(data)), 0, nil
}

func (f *fakeRemoteISOClient) CopyFileStream(ctx context.Context, localPath, remotePath string) error {
	if f.copyErr != nil && (f.copyErrFor == "" || f.copyErrFor == remotePath) {
		return f.copyErr
	}
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	buf, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	f.remoteFiles[remotePath] = buf
	f.uploaded = append(f.uploaded, remotePath)
	return nil
}

// errFakeRemote is a typed sentinel used only by the fake client to
// signal a missing path on operations other than StatRemote.
type errFakeRemote struct {
	Op   string
	Path string
}

func (e errFakeRemote) Error() string {
	return "fake remote: " + e.Op + " on missing path " + e.Path
}

// stagerTestEnv wires up a sshISOStager with a fakeRemoteISOClient and a
// scratch local ISO populated with the requested bytes. The previous
// newRemoteISOClient factory is restored on test cleanup.
type stagerTestEnv struct {
	stager     *sshISOStager
	fake       *fakeRemoteISOClient
	localPath  string
	remotePath string
	metaPath   string
}

func newStagerTestEnv(t *testing.T, localBytes []byte) *stagerTestEnv {
	t.Helper()

	dir := t.TempDir()
	localPath := filepath.Join(dir, "platform.iso")
	if err := os.WriteFile(localPath, localBytes, 0o644); err != nil {
		t.Fatalf("write local iso: %v", err)
	}

	fake := newFakeRemoteISOClient()
	prev := newRemoteISOClient
	newRemoteISOClient = func(host string, port int, user, keyPath, knownHostsPath string) (remoteISOClient, error) {
		return fake, nil
	}
	t.Cleanup(func() { newRemoteISOClient = prev })

	cfg := &DeployerConfig{
		Host:    "deploy.test",
		User:    "test",
		SSHKey:  "/dev/null",
		SMBHost: "deploy.test",
	}
	stager := &sshISOStager{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	remotePath := deployer.DefaultRemoteDataDir + "/" + filepath.Base(localPath)
	return &stagerTestEnv{
		stager:     stager,
		fake:       fake,
		localPath:  localPath,
		remotePath: remotePath,
		metaPath:   remotePath + stageMetaSuffix,
	}
}

// seedSidecar pre-populates the fake remote host with both the staged ISO
// bytes and a sidecar that records (size, sha256) of remoteBytes. Used by
// reuse-path tests.
func (env *stagerTestEnv) seedSidecar(t *testing.T, remoteBytes []byte) {
	t.Helper()
	env.fake.remoteFiles[env.remotePath] = append([]byte(nil), remoteBytes...)
	sum := sha256.Sum256(remoteBytes)
	meta := stageMeta{Size: int64(len(remoteBytes)), SHA256: hex.EncodeToString(sum[:])}
	payload, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	env.fake.remoteFiles[env.metaPath] = payload
}

func TestSSHISOStager_SkipsWhenSidecarAndSizeMatch(t *testing.T) {
	body := []byte("identical-iso-bytes")
	env := newStagerTestEnv(t, body)
	env.seedSidecar(t, body)

	url, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if !strings.HasPrefix(url, "smb://") {
		t.Fatalf("expected smb:// URL, got %q", url)
	}
	if len(env.fake.uploaded) != 0 {
		t.Fatalf("expected no upload when sidecar matches, got uploads: %v", env.fake.uploaded)
	}
	// The freshness path must have read the sidecar (cat command).
	var sawCat bool
	for _, c := range env.fake.commands {
		if strings.HasPrefix(c, "cat '") {
			sawCat = true
			break
		}
	}
	if !sawCat {
		t.Fatalf("expected sidecar cat command, got commands=%v", env.fake.commands)
	}
}

func TestSSHISOStager_UploadsWhenSidecarSizeMatchesButHashDiffers(t *testing.T) {
	local := []byte("AAAAAAAAAAAAAAAAAAAA")  // 20 bytes
	remote := []byte("BBBBBBBBBBBBBBBBBBBB") // same length, different bytes
	if len(local) != len(remote) {
		t.Fatalf("test setup error: lengths must match")
	}
	env := newStagerTestEnv(t, local)
	env.seedSidecar(t, remote)

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	// Two uploads expected: ISO + sidecar.
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads, got %v", env.fake.uploaded)
	}
	if !env.fake.connected || !env.fake.closed {
		t.Fatalf("SSH session connected=%v closed=%v; want it opened and released", env.fake.connected, env.fake.closed)
	}
	if got := env.fake.remoteFiles[env.remotePath]; string(got) != string(local) {
		t.Fatalf("remote bytes after upload: got %q want %q", got, local)
	}
	// Sidecar must reflect the new bytes.
	assertSidecarMatches(t, env.fake.remoteFiles[env.metaPath], local)
}

func TestSSHISOStager_UploadsWhenSidecarSizeDiffers(t *testing.T) {
	local := []byte("local-bytes-larger-payload")
	remote := []byte("smaller")
	env := newStagerTestEnv(t, local)
	env.seedSidecar(t, remote)

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads, got %v", env.fake.uploaded)
	}
	assertSidecarMatches(t, env.fake.remoteFiles[env.metaPath], local)
}

func TestSSHISOStager_UploadsWhenRemoteMissing(t *testing.T) {
	env := newStagerTestEnv(t, []byte("anything"))
	// remoteFiles map is empty -> remote file is missing.

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads for missing remote, got %v", env.fake.uploaded)
	}
	assertSidecarMatches(t, env.fake.remoteFiles[env.metaPath], []byte("anything"))
}

func TestSSHISOStager_UploadsWhenSidecarMissing(t *testing.T) {
	body := []byte("staged-iso-without-sidecar")
	env := newStagerTestEnv(t, body)
	// Pre-seed the staged ISO but NOT the sidecar — common after a
	// migration from the old size+mtime stager.
	env.fake.remoteFiles[env.remotePath] = append([]byte(nil), body...)

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads when sidecar missing, got %v", env.fake.uploaded)
	}
	assertSidecarMatches(t, env.fake.remoteFiles[env.metaPath], body)
}

func TestSSHISOStager_UploadsWhenSidecarUnparseable(t *testing.T) {
	body := []byte("staged-iso-corrupt-sidecar")
	env := newStagerTestEnv(t, body)
	env.fake.remoteFiles[env.remotePath] = append([]byte(nil), body...)
	env.fake.remoteFiles[env.metaPath] = []byte("{not valid json")

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads on corrupt sidecar, got %v", env.fake.uploaded)
	}
	assertSidecarMatches(t, env.fake.remoteFiles[env.metaPath], body)
}

func TestSSHISOStager_UploadsWhenSidecarHashIsMalformed(t *testing.T) {
	body := []byte("hash-not-hex")
	env := newStagerTestEnv(t, body)
	env.fake.remoteFiles[env.remotePath] = append([]byte(nil), body...)
	// Valid JSON but sha256 isn't 64 hex chars -> ErrInvalidStageMeta -> re-upload.
	bad := stageMeta{Size: int64(len(body)), SHA256: "not-a-sha"}
	payload, _ := json.Marshal(bad)
	env.fake.remoteFiles[env.metaPath] = payload

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar uploads on malformed hash, got %v", env.fake.uploaded)
	}
}

func TestSSHISOStager_UploadsWhenStagedSizeDriftsFromSidecar(t *testing.T) {
	body := []byte("size-drift-detection")
	env := newStagerTestEnv(t, body)
	// Sidecar claims one size; the staged file on disk is a different size.
	// This catches out-of-band tampering with the staged ISO.
	differentlySizedStaged := []byte("size-drift")
	env.fake.remoteFiles[env.remotePath] = differentlySizedStaged
	meta := stageMeta{Size: int64(len(body)), SHA256: hashHex(body)}
	payload, _ := json.Marshal(meta)
	env.fake.remoteFiles[env.metaPath] = payload

	if _, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath); err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if len(env.fake.uploaded) != 2 {
		t.Fatalf("expected ISO + sidecar re-upload on staged size drift, got %v", env.fake.uploaded)
	}
}

func TestSSHISOStager_PropagatesUnexpectedStatError(t *testing.T) {
	env := newStagerTestEnv(t, []byte("payload"))
	transportErr := errors.New("network blip")
	env.fake.statErr = transportErr

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail on transport stat error")
	}
	var staged ErrISOStagingFailed
	if !errors.As(err, &staged) {
		t.Fatalf("expected ErrISOStagingFailed, got %T: %v", err, err)
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("expected wrapped transport error to be reachable via errors.Is; got %v", err)
	}
}

func TestSSHISOStager_PropagatesUnexpectedRunError(t *testing.T) {
	body := []byte("payload")
	env := newStagerTestEnv(t, body)
	// Make Run fail. mkdir is the first Run() call so it fails the
	// staging upfront, but the typed error chain must still surface
	// the transport error.
	transportErr := errors.New("ssh exec failed")
	env.fake.runErr = transportErr

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail on transport run error")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("expected transport error in chain, got %v", err)
	}
}

func TestSSHISOStager_FailsTypedWhenSidecarUploadFails(t *testing.T) {
	body := []byte("upload-then-sidecar-fail")
	env := newStagerTestEnv(t, body)
	// Trigger ISO upload (no staged file yet), then fail the sidecar
	// upload specifically. The freshness-check error type must be in
	// the error chain.
	uploadErr := errors.New("disk full")
	env.fake.copyErr = uploadErr
	env.fake.copyErrFor = env.metaPath

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail when sidecar upload fails")
	}
	var fresh ErrISOStageFreshnessCheck
	if !errors.As(err, &fresh) {
		t.Fatalf("expected ErrISOStageFreshnessCheck in chain, got %T: %v", err, err)
	}
	if !errors.Is(err, uploadErr) {
		t.Fatalf("expected wrapped upload error in chain, got %v", err)
	}
}

func TestSSHISOStager_FailsTypedWhenISOUploadFails(t *testing.T) {
	body := []byte("iso-upload-fail")
	env := newStagerTestEnv(t, body)
	// Fail the ISO upload itself (no copyErrFor -> all CopyFileStream
	// calls fail).
	uploadErr := errors.New("connection reset")
	env.fake.copyErr = uploadErr

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail when ISO upload fails")
	}
	var staged ErrISOStagingFailed
	if !errors.As(err, &staged) {
		t.Fatalf("expected ErrISOStagingFailed, got %T: %v", err, err)
	}
}

func TestSSHISOStager_FailsTypedWhenConnectFails(t *testing.T) {
	env := newStagerTestEnv(t, []byte("payload"))
	connectErr := errors.New("ssh handshake failed")
	env.fake.connectErr = connectErr

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail when Connect fails")
	}
	if !errors.Is(err, connectErr) {
		t.Fatalf("expected connect error in chain, got %v", err)
	}
}

func TestSSHISOStager_LogsButTolerantOfCloseError(t *testing.T) {
	body := []byte("close-tolerance")
	env := newStagerTestEnv(t, body)
	env.seedSidecar(t, body)
	env.fake.closeErr = errors.New("ssh close failed")

	// Even with a Close failure, a fresh-cache call must still return
	// the SMB URL — the deferred close error is logged, not returned.
	url, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err != nil {
		t.Fatalf("StageVirtualMediaISO: unexpected error: %v", err)
	}
	if !strings.HasPrefix(url, "smb://") {
		t.Fatalf("expected smb:// URL even with close failure, got %q", url)
	}
	if !env.fake.closed {
		t.Fatalf("expected Close to have been invoked")
	}
}

func TestSSHISOStager_FailsTypedWhenClientFactoryFails(t *testing.T) {
	env := newStagerTestEnv(t, []byte("payload"))
	factoryErr := errors.New("dial timeout")
	prev := newRemoteISOClient
	newRemoteISOClient = func(host string, port int, user, keyPath, knownHostsPath string) (remoteISOClient, error) {
		return nil, factoryErr
	}
	t.Cleanup(func() { newRemoteISOClient = prev })

	_, err := env.stager.StageVirtualMediaISO(context.Background(), env.localPath)
	if err == nil {
		t.Fatalf("expected staging to fail when client factory fails")
	}
	if !errors.Is(err, factoryErr) {
		t.Fatalf("expected factory error in chain, got %v", err)
	}
}

func TestSSHISOStager_FailsTypedWhenLocalISOMissing(t *testing.T) {
	env := newStagerTestEnv(t, []byte("placeholder"))
	bogus := filepath.Join(t.TempDir(), "does-not-exist.iso")

	_, err := env.stager.StageVirtualMediaISO(context.Background(), bogus)
	if err == nil {
		t.Fatalf("expected staging to fail for missing local iso")
	}
	var staged ErrISOStagingFailed
	if !errors.As(err, &staged) {
		t.Fatalf("expected ErrISOStagingFailed, got %T: %v", err, err)
	}
}

func TestSSHISOStager_FailsTypedWhenLocalISOIsDirectory(t *testing.T) {
	env := newStagerTestEnv(t, []byte("placeholder"))
	dir := t.TempDir()

	// Pointing at a directory triggers sha256File's open-then-Read
	// failure path, which must surface as ErrISOStageFreshnessCheck.
	_, err := env.stager.StageVirtualMediaISO(context.Background(), dir)
	if err == nil {
		t.Fatalf("expected staging to fail for directory local path")
	}
	// Either the os.Stat detected a directory and we wrap directly, or
	// sha256File hit the read-of-directory failure; both routes go
	// through ErrISOStagingFailed.
	var staged ErrISOStagingFailed
	if !errors.As(err, &staged) {
		t.Fatalf("expected ErrISOStagingFailed, got %T: %v", err, err)
	}
	_ = env
}

func TestNewISOStager_ValidatesConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name string
		cfg  *DeployerConfig
	}{
		{"nil-cfg", nil},
		{"missing-host", &DeployerConfig{User: "u", SSHKey: "/k"}},
		{"missing-user", &DeployerConfig{Host: "h", SSHKey: "/k"}},
		{"missing-key", &DeployerConfig{Host: "h", User: "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newISOStager(tc.cfg, logger); err == nil {
				t.Fatalf("expected validation error for case %s", tc.name)
			}
		})
	}
}

func TestNewISOStager_AcceptsValidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &DeployerConfig{Host: "h", User: "u", SSHKey: "/k"}
	stager, err := newISOStager(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stager == nil {
		t.Fatalf("expected non-nil stager")
	}
}

func TestExpandTilde(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	cases := []struct {
		in, want string
	}{
		{"~", "/home/test"},
		{"~/.ssh/id_rsa", "/home/test/.ssh/id_rsa"},
		{"/abs/path", "/abs/path"},
		{"relative/path", "relative/path"},
	}
	for _, tc := range cases {
		got := expandTilde(tc.in)
		if got != tc.want {
			t.Errorf("expandTilde(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandTilde_NoHome(t *testing.T) {
	t.Setenv("HOME", "")
	// On systems where UserHomeDir falls back to other env vars, this
	// may still resolve. We only assert that the function does not panic
	// and returns *some* string for a tilde input.
	got := expandTilde("~/x")
	if got == "" {
		t.Fatalf("expandTilde returned empty string")
	}
}

func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iso")
	contents := []byte("hello iso")
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	want := hex.EncodeToString(sum[:])
	got, err := sha256File(path)
	if err != nil {
		t.Fatalf("sha256File: %v", err)
	}
	if got != want {
		t.Fatalf("sha256File: got %q want %q", got, want)
	}
}

func TestSha256File_Missing(t *testing.T) {
	if _, err := sha256File("/no/such/file/iso-stager-test"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestReadStageMeta_RejectsZeroSize(t *testing.T) {
	fake := newFakeRemoteISOClient()
	bad := stageMeta{Size: 0, SHA256: hashHex([]byte("x"))}
	payload, _ := json.Marshal(bad)
	fake.remoteFiles["/m"] = payload

	_, err := readStageMeta(context.Background(), fake, "/m")
	if err == nil {
		t.Fatalf("expected error for zero size")
	}
	var fresh ErrISOStageFreshnessCheck
	if !errors.As(err, &fresh) {
		t.Fatalf("expected ErrISOStageFreshnessCheck, got %T: %v", err, err)
	}
	var bad2 ErrInvalidStageMeta
	if !errors.As(err, &bad2) || bad2.Field != "size" {
		t.Fatalf("expected ErrInvalidStageMeta on size, got %v", err)
	}
}

func TestReadStageMeta_RejectsNonHexSha(t *testing.T) {
	fake := newFakeRemoteISOClient()
	// 64 chars but not hex.
	notHex := strings.Repeat("z", sha256.Size*2)
	bad := stageMeta{Size: 1, SHA256: notHex}
	payload, _ := json.Marshal(bad)
	fake.remoteFiles["/m"] = payload

	_, err := readStageMeta(context.Background(), fake, "/m")
	if err == nil {
		t.Fatalf("expected error for non-hex sha")
	}
	var bad2 ErrInvalidStageMeta
	if !errors.As(err, &bad2) || bad2.Field != "sha256" {
		t.Fatalf("expected ErrInvalidStageMeta on sha256, got %v", err)
	}
}

func TestReadStageMeta_PropagatesRunError(t *testing.T) {
	fake := newFakeRemoteISOClient()
	transport := errors.New("ssh down")
	fake.runErr = transport
	if _, err := readStageMeta(context.Background(), fake, "/m"); !errors.Is(err, transport) {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestErrISOStageFreshnessCheck_FormatsBothShapes(t *testing.T) {
	withCause := ErrISOStageFreshnessCheck{Path: "/p", Cause: errors.New("boom")}
	if !strings.Contains(withCause.Error(), "boom") || !strings.Contains(withCause.Error(), "/p") {
		t.Errorf("with-cause Error() missing detail: %s", withCause.Error())
	}
	if got := withCause.Unwrap(); got == nil || got.Error() != "boom" {
		t.Errorf("Unwrap should return the cause")
	}
	bare := ErrISOStageFreshnessCheck{Path: "/p"}
	if !strings.Contains(bare.Error(), "/p") {
		t.Errorf("bare Error() missing path: %s", bare.Error())
	}
}

func TestErrInvalidStageMeta_Formats(t *testing.T) {
	e := ErrInvalidStageMeta{Field: "size", Value: -1}
	if !strings.Contains(e.Error(), "size") {
		t.Errorf("Error() missing field name: %s", e.Error())
	}
}

// hashHex returns the lowercase-hex sha256 of payload; helper for tests
// that need to construct sidecars by hand.
func hashHex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// assertSidecarMatches decodes payload as a stageMeta and verifies it
// records the size and sha256 of expected.
func assertSidecarMatches(t *testing.T, payload []byte, expected []byte) {
	t.Helper()
	var meta stageMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		t.Fatalf("sidecar payload not JSON: %v (raw=%q)", err, string(payload))
	}
	if meta.Size != int64(len(expected)) {
		t.Errorf("sidecar size: got %d want %d", meta.Size, len(expected))
	}
	if meta.SHA256 != hashHex(expected) {
		t.Errorf("sidecar sha256: got %s want %s", meta.SHA256, hashHex(expected))
	}
}
