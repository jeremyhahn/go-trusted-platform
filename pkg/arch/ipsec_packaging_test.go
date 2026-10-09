package arch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
