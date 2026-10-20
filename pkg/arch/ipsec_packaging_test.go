package arch

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec"
)

// The overlay IPsec packaging (#709) spreads one set of facts -- the plugin
// set, the VICI and p11-kit socket paths, the p11-kit 0.26 pin -- over the
// aports, the OpenRC scripts, the builder Makefile and the integration suite.
// None of those can import a shared constant, so this guard fails when two of
// them disagree, before the disagreement reaches an image.

const (
	builderDir       = "build/docker/strongswan-builder"
	strongSwanAport  = builderDir + "/aport"
	p11HostAport     = builderDir + "/aport-p11-host"
	ipsecSuiteDir    = "test/integration/ipsec"
	viciSocketPath   = "/run/charon.vici"
	p11KitSocketPath = "/run/p11-kit/xkms.sock"
	p11HostUser      = "xkms-p11"
	p11TokenLabel    = "trusted-platform-ipsec"
)

// PackagingFileError reports a packaging file the guard could not read.
type PackagingFileError struct {
	Path string
	Err  error
}

func (e *PackagingFileError) Error() string {
	return "ipsec packaging: reading " + e.Path + ": " + e.Err.Error()
}

func (e *PackagingFileError) Unwrap() error { return e.Err }

// PackagingMismatchError reports a packaging file that lacks a fact another
// file states.
type PackagingMismatchError struct {
	Path string
	Want string
}

func (e *PackagingMismatchError) Error() string {
	return "ipsec packaging: " + e.Path + " does not contain " + e.Want
}

// readPackagingFile returns the contents of a repository file.
func readPackagingFile(root, rel string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return "", &PackagingFileError{Path: rel, Err: err}
	}
	return string(data), nil
}

// requireContains reports whether the repository file holds every fact.
func requireContains(root, rel string, facts ...string) error {
	content, err := readPackagingFile(root, rel)
	if err != nil {
		return err
	}
	for _, fact := range facts {
		if !strings.Contains(content, fact) {
			return &PackagingMismatchError{Path: rel, Want: fact}
		}
	}
	return nil
}

func TestRequireContains(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.conf"), []byte("socket = /run/x\n"), 0o600))

	t.Run("holds every fact", func(t *testing.T) {
		assert.NoError(t, requireContains(root, "a.conf", "socket", "/run/x"))
	})
	t.Run("a missing fact is a mismatch", func(t *testing.T) {
		var mismatch *PackagingMismatchError
		err := requireContains(root, "a.conf", "socket", "/run/y")
		require.ErrorAs(t, err, &mismatch)
		assert.Equal(t, "/run/y", mismatch.Want)
	})
	t.Run("a missing file is a read error", func(t *testing.T) {
		var readErr *PackagingFileError
		err := requireContains(root, "absent.conf", "x")
		require.ErrorAs(t, err, &readErr)
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})
}

func TestIPsecPackaging_PluginSetIsOneList(t *testing.T) {
	root := repoRoot(t)
	makefile, err := readPackagingFile(root, builderDir+"/Makefile")
	require.NoError(t, err)

	var plugins string
	for _, line := range strings.Split(makefile, "\n") {
		if rest, ok := strings.CutPrefix(line, "STRONGSWAN_PLUGINS ?="); ok {
			plugins = strings.TrimSpace(rest)
		}
	}
	require.NotEmpty(t, plugins, "builder Makefile has no STRONGSWAN_PLUGINS")
	// The brief's set: the four the overlay needs, and what they depend on.
	for _, plugin := range []string{"openssl", "pkcs11", "vici"} {
		assert.Contains(t, strings.Fields(plugins), plugin)
	}

	// Both the aport's check and the shipped strongswan.d load list take the
	// Makefile's set through the same placeholder.
	require.NoError(t, requireContains(root, strongSwanAport+"/APKBUILD", `_plugins="@STRONGSWAN_PLUGINS@"`))
	require.NoError(t, requireContains(root, strongSwanAport+"/trusted-platform.conf", "load = @STRONGSWAN_PLUGINS@"))
}

func TestIPsecPackaging_SocketPathsAgree(t *testing.T) {
	root := repoRoot(t)
	tests := map[string]struct {
		file  string
		facts []string
	}{
		"strongswan.d vici socket":  {strongSwanAport + "/trusted-platform.conf", []string{"unix://" + viciSocketPath}},
		"charon service vici":       {strongSwanAport + "/charon.initd", []string{`vici_socket="` + viciSocketPath + `"`}},
		"suite vici":                {ipsecSuiteDir + "/harness_test.go", []string{`"` + viciSocketPath + `"`}},
		"charon p11-kit address":    {strongSwanAport + "/charon.confd", []string{"unix:path=" + p11KitSocketPath}},
		"module host service":       {p11HostAport + "/xkms-p11-kit.initd", []string{`socket_dir="/run/p11-kit"`, `socket="${socket_dir}/xkms.sock"`}},
		"suite p11-kit socket":      {ipsecSuiteDir + "/harness_test.go", []string{`"` + p11KitSocketPath + `"`}},
		"charon needs module host":  {strongSwanAport + "/charon.initd", []string{"xkms-p11-kit"}},
		"pkcs11 plugin module path": {strongSwanAport + "/pkcs11.conf", []string{"/usr/lib/pkcs11/p11-kit-client.so"}},
		// load-token names the module by its strongswan.conf section.
		"pkcs11 plugin module name": {strongSwanAport + "/pkcs11.conf", []string{"\t\t" + ipsec.DefaultTokenModule + " {"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, requireContains(root, tt.file, tt.facts...))
		})
	}

	// platformd dials what charon serves.
	assert.Equal(t, viciSocketPath, ipsec.DefaultVICISocket)
}

func TestIPsecPackaging_P11KitPinIsConsistent(t *testing.T) {
	root := repoRoot(t)
	tests := map[string]struct {
		file string
		fact string
	}{
		"charon apk depends on the client": {strongSwanAport + "/APKBUILD", "p11-kit-server>=0.26"},
		"module host apk depends":          {p11HostAport + "/APKBUILD", "p11-kit-server>=0.26"},
		"module host build refuses older":  {builderDir + "/modulehost/Dockerfile", "ge 0.26"},
		"pin check minimum":                {p11HostAport + "/p11-kit-pin-check", "min_minor=26"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, requireContains(root, tt.file, tt.fact))
		})
	}
}

// TestP11KitPinCheck runs the shipped check, which the apk build and the
// service both run on the module host's recorded p11-kit version.
func TestP11KitPinCheck(t *testing.T) {
	script := filepath.Join(repoRoot(t), p11HostAport, "p11-kit-pin-check")
	tests := map[string]struct {
		version string
		exit    int
	}{
		"the pinned version":        {"0.26.2", 0},
		"a distro revision":         {"0.26.2-1ubuntu1", 0},
		"a later minor":             {"0.27.0", 0},
		"a later major":             {"1.0", 0},
		"two-digit minor":           {"0.100.1", 0},
		"trixie's 0.25":             {"0.25.5", 1},
		"bookworm's 0.24":           {"0.24.1-2", 1},
		"an old single digit minor": {"0.9", 1},
		"not a version":             {"abc", 2},
		"empty":                     {"", 2},
		"major only":                {"1", 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := exec.Command("/bin/sh", script, tt.version).Run()
			if tt.exit == 0 {
				require.NoError(t, err)
				return
			}
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			assert.Equal(t, tt.exit, exit.ExitCode())
		})
	}
}

// Both services run their daemon under the shipped socket-takeover, so the
// socket is handed over after every respawn, not at the next health check.
func TestIPsecPackaging_ServicesRunUnderSocketTakeover(t *testing.T) {
	root := repoRoot(t)
	tests := map[string]struct {
		file  string
		facts []string
	}{
		"builder image carries it":  {builderDir + "/Dockerfile", []string{"COPY socket-takeover /build/"}},
		"both aports are staged it": {builderDir + "/build-strongswan.sh", []string{`/build/socket-takeover "$aport/"`}},
		"charon apk installs it":    {strongSwanAport + "/APKBUILD", []string{"\tsocket-takeover\n", `"$pkgdir"/usr/lib/strongswan/socket-takeover`}},
		"charon runs under it":      {strongSwanAport + "/charon.initd", []string{`command="/usr/lib/strongswan/socket-takeover"`}},
		"module host apk installs":  {p11HostAport + "/APKBUILD", []string{"\tsocket-takeover\n", `"$pkgdir"/usr/libexec/xkms-p11-host/socket-takeover`}},
		"module host runs under it": {p11HostAport + "/xkms-p11-kit.initd", []string{`libexec="/usr/libexec/xkms-p11-host"`, `command="${libexec}/socket-takeover"`}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, requireContains(root, tt.file, tt.facts...))
		})
	}
}

// TestIPsecPackaging_PlatformdReachesCharon: an installed node gives the
// VICI socket to the account platformd runs as (root: neither generated
// platformd script sets command_user, and the VICI dialer refuses a socket
// its own uid does not own), enables both IPsec services at boot, and starts
// platformd after charon.
func TestIPsecPackaging_PlatformdReachesCharon(t *testing.T) {
	root := repoRoot(t)
	tests := map[string]struct {
		file  string
		facts []string
	}{
		"charon gives the socket to root":     {strongSwanAport + "/charon.initd", []string{`vici_user="${CHARON_VICI_USER:-root}"`, `vici_group="${CHARON_VICI_GROUP:-root}"`}},
		"its conf.d documents that default":   {strongSwanAport + "/charon.confd", []string{`#CHARON_VICI_USER="root"`, `#CHARON_VICI_GROUP="root"`}},
		"the installer enables both at boot":  {"pkg/installer/alpine.go", []string{`{name: "xkms-p11-kit", runlevel: "default"}`, `{name: "charon", runlevel: "default"}`}},
		"installed platformd follows charon":  {"pkg/installer/installer.go", []string{"after tpm-firstboot-seal charon\n"}},
		"first-boot platformd follows charon": {"pkg/firstboot/executor.go", []string{"after firewall charon\n"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, requireContains(root, tt.file, tt.facts...))
		})
	}
	for _, file := range []string{"pkg/installer/installer.go", "pkg/firstboot/executor.go"} {
		body, err := readPackagingFile(root, file)
		require.NoError(t, err)
		assert.NotContains(t, body, "command_user", "%s: platformd must run as root, the VICI socket's owner", file)
	}
}

// The module host exports the IPsec token alone, and its p11-kit server runs
// as the module host's own unprivileged user. The service keeps root only for
// the chroot and the socket handover; the server drops to the user inside the
// chroot.
func TestIPsecPackaging_ModuleHostIsConfined(t *testing.T) {
	root := repoRoot(t)
	initd := p11HostAport + "/xkms-p11-kit.initd"
	tests := map[string]struct {
		file  string
		facts []string
	}{
		"the apk creates the user": {p11HostAport + "/APKBUILD", []string{
			`pkgusers="` + p11HostUser + `"`, `pkggroups="` + p11HostUser + `"`, `install="$pkgname.pre-install"`}},
		"the pre-install adds it": {p11HostAport + "/trusted-platform-p11-host.pre-install", []string{
			"addgroup -S " + p11HostUser, "-G " + p11HostUser + " -g " + p11HostUser + " " + p11HostUser}},
		"the builder creates it ahead of abuild": {builderDir + "/Dockerfile", []string{
			"addgroup -S " + p11HostUser, "-G " + p11HostUser + " " + p11HostUser}},
		"the root filesystem can drop to it": {builderDir + "/modulehost/Dockerfile", []string{"test -x /usr/bin/setpriv"}},
		"the service names it":               {initd, []string{`p11_user="` + p11HostUser + `"`}},
		"the server drops to it": {initd, []string{
			`drop="/usr/bin/setpriv --reuid=${p11_uid} --regid=${p11_gid} --clear-groups --no-new-privs"`,
			"/usr/sbin/chroot ${host_root} ${drop} /usr/bin/p11-kit server"}},
		"the takeover waits for it":     {initd, []string{"${socket} ${p11_user} ${p11_user}:${socket_group} 0660"}},
		"it owns the state":             {initd, []string{`checkpath -d -m 0700 -o "${p11_user}:${p11_user}" "${state_dir}"`}},
		"it creates the socket":         {initd, []string{`checkpath -d -m 0755 -o "${p11_user}:${p11_user}" "${socket_dir}"`}},
		"the export is the IPsec token": {initd, []string{`token_label="` + p11TokenLabel + `"`, `token_uri="pkcs11:token=${token_label}"`, "--provider ${module} ${token_uri}"}},
		"root labels the token":         {initd, []string{`extra_stopped_commands="init_token"`, `--init-token --label "${token_label}"`}},
		"the root filesystem can label": {builderDir + "/modulehost/Dockerfile", []string{"test -x /usr/bin/pkcs11-tool"}},
		"the suite labels it as root":   {ipsecSuiteDir + "/harness_test.go", []string{`"rc-service", "xkms-p11-kit", "init_token"`}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, requireContains(root, tt.file, tt.facts...))
		})
	}

	// No line of the service exports a URI that names no token.
	content, err := readPackagingFile(root, initd)
	require.NoError(t, err)
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for rest := line; ; {
			_, after, found := strings.Cut(rest, "pkcs11:")
			if !found {
				break
			}
			assert.True(t, strings.HasPrefix(after, "token="), "unscoped PKCS#11 URI in %s: %s", initd, line)
			rest = after
		}
	}
}

// takeoverDaemonEnv turns the test binary into the daemon the socket-takeover
// tests run: it listens on the socket the variable names, at mode 0755, and
// serves until SIGTERM, then exits 0.
const takeoverDaemonEnv = "ARCH_TEST_TAKEOVER_DAEMON"

func TestMain(m *testing.M) {
	if path := os.Getenv(takeoverDaemonEnv); path != "" {
		os.Exit(serveTakeoverSocket(path))
	}
	os.Exit(m.Run())
}

// serveTakeoverSocket is the daemon; it exits 1 if it cannot serve path.
func serveTakeoverSocket(path string) int {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Chmod(path, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	<-stop
	if err := ln.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// startTakeover runs the shipped socket-takeover with args and the extra
// environment; done yields its exit. It is killed at cleanup if still running.
func startTakeover(t *testing.T, env []string, args ...string) (cmd *exec.Cmd, done <-chan error) {
	t.Helper()
	script := filepath.Join(repoRoot(t), builderDir, "socket-takeover")
	cmd = exec.Command("/bin/sh", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	require.NoError(t, cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("kill socket-takeover: %v", err)
		}
	})
	return cmd, exited
}

// awaitExit waits for socket-takeover to exit on its own.
func awaitExit(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("socket-takeover did not exit")
		return nil
	}
}

// awaitSocketMode waits for path to be a socket of mode, failing if
// socket-takeover exits first.
func awaitSocketMode(t *testing.T, done <-chan error, path string, mode fs.FileMode) {
	t.Helper()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(10 * time.Second)
	for {
		if fi, err := os.Lstat(path); err == nil && fi.Mode().Type() == fs.ModeSocket && fi.Mode().Perm() == mode {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("socket-takeover exited before the takeover: %v", err)
		case <-deadline:
			t.Fatalf("%s never became a socket of mode %v", path, mode)
		case <-tick.C:
		}
	}
}

func TestSocketTakeoverHandsTheSocketOver(t *testing.T) {
	me, err := user.Current()
	require.NoError(t, err)
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	// A socket file left by a daemon that died is removed first; the daemon
	// could not listen over it.
	require.NoError(t, os.WriteFile(socket, nil, 0o600))

	cmd, done := startTakeover(t, []string{takeoverDaemonEnv + "=" + socket},
		socket, me.Username, me.Uid+":"+me.Gid, "0600", os.Args[0])
	awaitSocketMode(t, done, socket, 0o600)

	// The daemon replaced the script's process, so the supervisor's signal
	// reaches the daemon itself, which exits cleanly.
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	assert.NoError(t, awaitExit(t, done))
}

func TestSocketTakeoverStopsADaemonThatNeverServes(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	_, done := startTakeover(t, []string{"SOCKET_TAKEOVER_TRIES=2"},
		socket, "root", "0:0", "0600", "sleep", "30")

	var exit *exec.ExitError
	require.ErrorAs(t, awaitExit(t, done), &exit)
	status, ok := exit.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	assert.Equal(t, syscall.SIGTERM, status.Signal(), "the daemon must be stopped so supervise-daemon respawns it")
}

func TestSocketTakeoverStopsTheDaemonWhenTheTakeoverFails(t *testing.T) {
	me, err := user.Current()
	require.NoError(t, err)
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	_, done := startTakeover(t, []string{takeoverDaemonEnv + "=" + socket},
		socket, me.Username, "no-such-user-709:no-such-group-709", "0600", os.Args[0])

	// The daemon exits only on SIGTERM; nothing but the failed takeover sends it.
	assert.NoError(t, awaitExit(t, done))
}

func TestSocketTakeoverUsage(t *testing.T) {
	_, done := startTakeover(t, nil, "/run/x.sock", "root", "0:0", "0600")
	var exit *exec.ExitError
	require.ErrorAs(t, awaitExit(t, done), &exit)
	assert.Equal(t, 2, exit.ExitCode())
}
