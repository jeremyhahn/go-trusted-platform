package iso

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runStaticCIDR executes the shipped shell helper under /bin/sh with the
// three network.conf fields the dracut hook passes it and returns stdout.
func runStaticCIDR(t *testing.T, address, prefix, netmask string) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "static-cidr.sh")
	require.NoError(t, os.WriteFile(helper, []byte(platformdStaticCIDRShell), 0600))
	cmd := exec.Command("/bin/sh", "-c", `. "$0" && platformd_static_cidr "$1" "$2" "$3"`, helper, address, prefix, netmask)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "helper output: %s", out)
	return strings.TrimSpace(string(out))
}

func TestPlatformdStaticCIDRShell_AppliesPrefixOnce(t *testing.T) {
	tests := []struct {
		name    string
		address string
		prefix  string
		netmask string
		want    string
	}{
		{name: "bare address with IPV4_PREFIX", address: "10.4.2.140", prefix: "24", want: "10.4.2.140/24"},
		{name: "cidr address without IPV4_PREFIX", address: "10.4.2.140/24", want: "10.4.2.140/24"},
		{name: "cidr address with matching IPV4_PREFIX", address: "10.4.2.140/24", prefix: "24", want: "10.4.2.140/24"},
		{name: "IPV4_PREFIX wins over cidr suffix", address: "10.4.2.140/24", prefix: "28", want: "10.4.2.140/28"},
		{name: "cidr suffix wins over netmask", address: "10.4.2.140/28", netmask: "255.255.255.0", want: "10.4.2.140/28"},
		{name: "bare address with netmask", address: "10.4.2.140", netmask: "255.255.255.128", want: "10.4.2.140/25"},
		{name: "bare address with wide netmask", address: "10.1.2.3", netmask: "255.255.0.0", want: "10.1.2.3/16"},
		{name: "host route netmask", address: "10.1.2.3", netmask: "255.255.255.255", want: "10.1.2.3/32"},
		{name: "bare address defaults to /24", address: "10.4.2.140", want: "10.4.2.140/24"},
		{name: "zero prefix is valid", address: "0.0.0.0", prefix: "0", want: "0.0.0.0/0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runStaticCIDR(t, tt.address, tt.prefix, tt.netmask)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, 1, strings.Count(got, "/"), "exactly one prefix separator")
		})
	}
}

func TestPlatformdStaticCIDRShell_MalformedFallsBack(t *testing.T) {
	tests := []struct {
		name    string
		address string
		prefix  string
		netmask string
		want    string
	}{
		{name: "doubled suffix from the #108 boot", address: "10.4.2.140/24/24", want: "10.4.2.140/24"},
		{name: "doubled suffix keeps a valid IPV4_PREFIX", address: "10.4.2.140/24/24", prefix: "28", want: "10.4.2.140/28"},
		{name: "empty suffix falls back to netmask", address: "10.4.2.140/", netmask: "255.255.255.192", want: "10.4.2.140/26"},
		{name: "non-numeric IPV4_PREFIX falls back to suffix", address: "10.4.2.140/25", prefix: "24a", want: "10.4.2.140/25"},
		{name: "IPV4_PREFIX out of range falls back to netmask", address: "10.4.2.140", prefix: "33", netmask: "255.255.255.0", want: "10.4.2.140/24"},
		{name: "suffix out of range falls back to default", address: "10.4.2.140/99", want: "10.4.2.140/24"},
		{name: "negative prefix falls back to default", address: "10.4.2.140", prefix: "-1", want: "10.4.2.140/24"},
		{name: "unknown netmask falls back to default", address: "10.4.2.140", netmask: "255.0.255.0", want: "10.4.2.140/24"},
		{name: "netmask written as a prefix falls back to default", address: "10.4.2.140", netmask: "24", want: "10.4.2.140/24"},
		{name: "shell metacharacters are not evaluated", address: "10.4.2.140/$(echo 1)", want: "10.4.2.140/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, runStaticCIDR(t, tt.address, tt.prefix, tt.netmask))
		})
	}
}

func TestCopyDracutModule_UnlockHookNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	isoDir := filepath.Join(tmpDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	customizer := NewCustomizer(&PlatformISOConfig{
		Directories: DirectoryConfig{
			ISO:     isoDir,
			Overlay: filepath.Join(tmpDir, "overlay"),
		},
	}, logging.DefaultLogger())
	require.NoError(t, customizer.CopyDracutModule(context.Background()))

	unlockScript := filepath.Join(isoDir, "dracut-platformd", "90platformd", "platformd-unlock.sh")
	raw, err := os.ReadFile(unlockScript)
	require.NoError(t, err)
	content := string(raw)

	t.Run("hook parses as POSIX sh", func(t *testing.T) {
		out, err := exec.Command("/bin/sh", "-n", unlockScript).CombinedOutput()
		assert.NoError(t, err, "sh -n output: %s", out)
	})

	t.Run("hook applies the helper's CIDR exactly once", func(t *testing.T) {
		assert.Contains(t, content, "platformd_static_cidr() {")
		assert.Contains(t, content, `NET_CIDR=$(platformd_static_cidr "$NET_IP" "$NET_PREFIX" "$NET_MASK")`)
		assert.Contains(t, content, `ip addr add "$NET_CIDR" dev "$NET_IFACE"`)
		assert.Contains(t, content, `NET_PREFIX="${IPV4_PREFIX:-}"`)
		assert.NotContains(t, content, `"$NET_IP/$PREFIX"`, "the hook must not append a prefix to the address itself")
		assert.NotContains(t, content, `IPV4_NETMASK:-255.255.255.0`, "a defaulted netmask would mask a prefix carried in the address")
	})

	t.Run("hook does not promise initramfs enrollment", func(t *testing.T) {
		assert.NotContains(t, content, "ACME enrollment may fail")
		assert.NotContains(t, content, "network for ACME enrollment")
		assert.Contains(t, content, "enrollment runs after switch_root")
	})
}

// busyboxBuildRoot is a build root holding what Alpine's busybox package
// installs for udhcpc: its lease script and its config.
func busyboxBuildRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{"usr/share/udhcpc/default.script", "etc/udhcpc/udhcpc.conf"} {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
	}
	return root
}

// runInstallNetwork runs platformd_install_network against root with dracut's
// install helpers stubbed to record what they install; inst_multiple reports
// the tools named in missing as absent. It returns the recorded installs and
// the function's exit status.
func runInstallNetwork(t *testing.T, root, cmdline string, missing ...string) ([]string, int) {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "install-network.sh")
	require.NoError(t, os.WriteFile(helper, []byte(platformdInstallNetworkShell), 0o600))
	cmdlineFile := filepath.Join(dir, "cmdline")
	require.NoError(t, os.WriteFile(cmdlineFile, []byte(cmdline+"\n"), 0o600))
	installed := filepath.Join(dir, "installed")

	script := `inst_multiple() { case " $MISSING " in *" $1 "*) return 1 ;; esac; echo "bin $1" >> "$INSTALLED"; }
inst_simple() { echo "file $1 -> $2" >> "$INSTALLED"; }
dinfo() { :; }; dwarn() { :; }; derror() { :; }
. "$0" && platformd_install_network "$1" "$2"`
	cmd := exec.Command("/bin/sh", "-c", script, helper, root, cmdlineFile)
	cmd.Env = append(os.Environ(), "INSTALLED="+installed, "MISSING="+strings.Join(missing, " "))
	out, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "shell did not run: %v: %s", err, out)
		status = exitErr.ExitCode()
	}

	raw, err := os.ReadFile(installed)
	if os.IsNotExist(err) {
		return nil, status
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(raw)), "\n"), status
}

func TestPlatformdInstallNetworkShell_InstallsTheDHCPClientAndItsScript(t *testing.T) {
	root := busyboxBuildRoot(t)
	installed, status := runInstallNetwork(t, root, disklessCmdline)

	require.Equal(t, 0, status)
	for _, want := range []string{
		"bin udhcpc", "bin ip", "bin cut", "bin chmod", "bin mv", "bin ping", "bin hostname",
		"file " + root + "/usr/share/udhcpc/default.script -> /usr/share/udhcpc/default.script",
		"file " + root + "/etc/udhcpc/udhcpc.conf -> /etc/udhcpc/udhcpc.conf",
	} {
		assert.Contains(t, installed, want)
	}
}

func TestPlatformdInstallNetworkShell_MissingPieces(t *testing.T) {
	scriptless := t.TempDir()
	tests := []struct {
		name       string
		root       string
		cmdline    string
		missing    []string
		wantStatus int
	}{
		{name: "a diskless node without the lease script", root: scriptless, cmdline: disklessCmdline, wantStatus: 1},
		{name: "a diskless node without udhcpc", cmdline: disklessCmdline, missing: []string{"udhcpc"}, wantStatus: 1},
		{name: "a diskless node without ip", cmdline: disklessCmdline, missing: []string{"ip"}, wantStatus: 1},
		{name: "a diskless node without the optional ping", cmdline: disklessCmdline, missing: []string{"ping"}, wantStatus: 0},
		{name: "a disk install only warns", root: scriptless, cmdline: diskCmdline, missing: []string{"udhcpc"}, wantStatus: 0},
		{name: "a diskless-nbd node without udhcpc", cmdline: nbdCmdline, missing: []string{"udhcpc"}, wantStatus: 1},
		{name: "a diskless-nbd node without the lease script", root: scriptless, cmdline: nbdCmdline, wantStatus: 1},
		{name: "a diskless-nbd node without the optional ping", cmdline: nbdCmdline, missing: []string{"ping"}, wantStatus: 0},
		{name: "a parameter that only contains the diskless-nbd model only warns", root: scriptless, cmdline: "x" + nbdCmdline, missing: []string{"udhcpc"}, wantStatus: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := tt.root
			if root == "" {
				root = busyboxBuildRoot(t)
			}
			_, status := runInstallNetwork(t, root, tt.cmdline, tt.missing...)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}
