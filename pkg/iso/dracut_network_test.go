package iso

import (
	"context"
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
		{name: "bare address with IPV4_PREFIX", address: "198.18.1.140", prefix: "24", want: "198.18.1.140/24"},
		{name: "cidr address without IPV4_PREFIX", address: "198.18.1.140/24", want: "198.18.1.140/24"},
		{name: "cidr address with matching IPV4_PREFIX", address: "198.18.1.140/24", prefix: "24", want: "198.18.1.140/24"},
		{name: "IPV4_PREFIX wins over cidr suffix", address: "198.18.1.140/24", prefix: "28", want: "198.18.1.140/28"},
		{name: "cidr suffix wins over netmask", address: "198.18.1.140/28", netmask: "255.255.255.0", want: "198.18.1.140/28"},
		{name: "bare address with netmask", address: "198.18.1.140", netmask: "255.255.255.128", want: "198.18.1.140/25"},
		{name: "bare address with wide netmask", address: "10.1.2.3", netmask: "255.255.0.0", want: "10.1.2.3/16"},
		{name: "host route netmask", address: "10.1.2.3", netmask: "255.255.255.255", want: "10.1.2.3/32"},
		{name: "bare address defaults to /24", address: "198.18.1.140", want: "198.18.1.140/24"},
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
		{name: "doubled suffix from the #108 boot", address: "198.18.1.140/24/24", want: "198.18.1.140/24"},
		{name: "doubled suffix keeps a valid IPV4_PREFIX", address: "198.18.1.140/24/24", prefix: "28", want: "198.18.1.140/28"},
		{name: "empty suffix falls back to netmask", address: "198.18.1.140/", netmask: "255.255.255.192", want: "198.18.1.140/26"},
		{name: "non-numeric IPV4_PREFIX falls back to suffix", address: "198.18.1.140/25", prefix: "24a", want: "198.18.1.140/25"},
		{name: "IPV4_PREFIX out of range falls back to netmask", address: "198.18.1.140", prefix: "33", netmask: "255.255.255.0", want: "198.18.1.140/24"},
		{name: "suffix out of range falls back to default", address: "198.18.1.140/99", want: "198.18.1.140/24"},
		{name: "negative prefix falls back to default", address: "198.18.1.140", prefix: "-1", want: "198.18.1.140/24"},
		{name: "unknown netmask falls back to default", address: "198.18.1.140", netmask: "255.0.255.0", want: "198.18.1.140/24"},
		{name: "netmask written as a prefix falls back to default", address: "198.18.1.140", netmask: "24", want: "198.18.1.140/24"},
		{name: "shell metacharacters are not evaluated", address: "198.18.1.140/$(echo 1)", want: "198.18.1.140/24"},
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
