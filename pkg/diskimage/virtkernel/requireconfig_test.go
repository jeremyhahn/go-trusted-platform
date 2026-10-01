package virtkernel

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The shared kernel configuration (build/docker/kernel-config) is a
// virt-kernel builder input — its two files are in configInputs and the
// image bakes them in — so this package, which owns that builder, also pins
// the check both kernel builders run.

// sharedKernelConfig returns build/docker/kernel-config/<name> in this
// checkout.
func sharedKernelConfig(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoBuilderDir(t), KernelConfigDir, name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shared kernel configuration missing: %v", err)
	}
	return path
}

// runRequireConfig runs the real require-config.sh and returns its exit
// code and combined output.
func runRequireConfig(t *testing.T, args ...string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatal("bash is required for this test")
	}
	script := sharedKernelConfig(t, "require-config.sh")
	out, err := exec.Command("bash", append([]string{script}, args...)...).CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running require-config.sh: %v", err)
	}
	return exit.ExitCode(), string(out)
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// testFragment exercises each requirement form: built in, module, a value,
// and a symbol that must stay unset; comments and blank lines are skipped.
const testFragment = `# a comment line, not a requirement

CONFIG_OPENVSWITCH=m
CONFIG_CRYPTO_FIPS=y
CONFIG_CRYPTO_FIPS_NAME="Trusted Platform"
# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set
`

// satisfyingConfig is a .config that meets testFragment exactly.
const satisfyingConfig = `CONFIG_OPENVSWITCH=m
CONFIG_CRYPTO_FIPS=y
CONFIG_CRYPTO_FIPS_NAME="Trusted Platform"
# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set
CONFIG_UNRELATED=y
`

func TestRequireConfig_AcceptsAConfigCarryingEveryLine(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	config := writeFile(t, dir, ".config", satisfyingConfig)
	if code, out := runRequireConfig(t, config, fragment); code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if code, out := runRequireConfig(t, "--enabled", config, fragment); code != 0 {
		t.Fatalf("--enabled: exit %d, want 0:\n%s", code, out)
	}
}

func TestRequireConfig_FailsWhenKconfigDroppedAnOption(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	config := writeFile(t, dir, ".config",
		strings.Replace(satisfyingConfig, "CONFIG_CRYPTO_FIPS=y\n", "# CONFIG_CRYPTO_FIPS is not set\n", 1))
	code, out := runRequireConfig(t, config, fragment)
	if code != 3 {
		t.Fatalf("exit %d, want 3:\n%s", code, out)
	}
	if !strings.Contains(out, "CONFIG_CRYPTO_FIPS=y was dropped by Kconfig") {
		t.Errorf("output does not name the dropped option:\n%s", out)
	}
	if strings.Contains(out, "CONFIG_OPENVSWITCH") {
		t.Errorf("output names an option that is present:\n%s", out)
	}
}

func TestRequireConfig_ReportsEveryMiss(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	config := writeFile(t, dir, ".config", "CONFIG_UNRELATED=y\n")
	code, out := runRequireConfig(t, config, fragment)
	if code != 3 {
		t.Fatalf("exit %d, want 3:\n%s", code, out)
	}
	for _, want := range []string{"CONFIG_OPENVSWITCH=m", "CONFIG_CRYPTO_FIPS=y", "CONFIG_CRYPTO_FIPS_NAME", "misses 3 required option(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRequireConfig_ExactModeRejectsADifferentTristate(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	// Built in where the fragment asks for a module, and a module where it
	// asks for built in: exact for the builders, enough for --enabled.
	body := strings.Replace(satisfyingConfig, "CONFIG_OPENVSWITCH=m", "CONFIG_OPENVSWITCH=y", 1)
	body = strings.Replace(body, "CONFIG_CRYPTO_FIPS=y", "CONFIG_CRYPTO_FIPS=m", 1)
	config := writeFile(t, dir, ".config", body)
	code, out := runRequireConfig(t, config, fragment)
	if code != 3 || !strings.Contains(out, "CONFIG_OPENVSWITCH=m") || !strings.Contains(out, "CONFIG_CRYPTO_FIPS=y") {
		t.Fatalf("exact mode: exit %d, want 3 naming both options:\n%s", code, out)
	}
	if code, out := runRequireConfig(t, "--enabled", config, fragment); code != 0 {
		t.Fatalf("--enabled: exit %d, want 0:\n%s", code, out)
	}
}

func TestRequireConfig_EnabledModeStillRequiresPresenceAndValues(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	body := strings.Replace(satisfyingConfig, "CONFIG_OPENVSWITCH=m\n", "", 1)
	body = strings.Replace(body, `"Trusted Platform"`, `"Other"`, 1)
	config := writeFile(t, dir, ".config", body)
	code, out := runRequireConfig(t, "--enabled", config, fragment)
	if code != 3 {
		t.Fatalf("exit %d, want 3:\n%s", code, out)
	}
	if !strings.Contains(out, "CONFIG_OPENVSWITCH is not enabled") || !strings.Contains(out, "CONFIG_CRYPTO_FIPS_NAME") {
		t.Errorf("output does not name both misses:\n%s", out)
	}
}

func TestRequireConfig_FailsWhenAnUnsetRequirementIsEnabled(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	config := writeFile(t, dir, ".config", strings.Replace(satisfyingConfig,
		"# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set", "CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y", 1))
	for _, mode := range [][]string{{config, fragment}, {"--enabled", config, fragment}} {
		code, out := runRequireConfig(t, mode...)
		if code != 3 || !strings.Contains(out, "CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set is violated") {
			t.Errorf("%v: exit %d, want 3 naming the violated requirement:\n%s", mode, code, out)
		}
	}
	// A symbol the .config does not mention at all is not set either.
	absent := writeFile(t, dir, "absent.config", strings.Replace(satisfyingConfig,
		"# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set\n", "", 1))
	if code, out := runRequireConfig(t, absent, fragment); code != 0 {
		t.Errorf("absent symbol: exit %d, want 0:\n%s", code, out)
	}
}

func TestRequireConfig_UsageAndInputErrors(t *testing.T) {
	dir := t.TempDir()
	fragment := writeFile(t, dir, "fragment.config", testFragment)
	config := writeFile(t, dir, ".config", satisfyingConfig)
	malformed := writeFile(t, dir, "malformed.config", "OPENVSWITCH=m\n")
	for name, args := range map[string][]string{
		"no fragment":         {config},
		"no arguments":        {},
		"unreadable config":   {filepath.Join(dir, "missing"), fragment},
		"unreadable fragment": {config, filepath.Join(dir, "missing")},
		"malformed fragment":  {config, malformed},
	} {
		if code, out := runRequireConfig(t, args...); code != 2 {
			t.Errorf("%s: exit %d, want 2:\n%s", name, code, out)
		}
	}
}

// requiredSymbols is the kernel option list of the v0.2.0 overlay design
// (docs/sdn/engineering.md, IPsec > Kernel configuration). The fragment may
// carry more (the dependencies), never less.
var requiredSymbols = []string{
	// datapath
	"CONFIG_OPENVSWITCH", "CONFIG_OPENVSWITCH_VXLAN", "CONFIG_VXLAN",
	// IPsec
	"CONFIG_INET_ESP", "CONFIG_INET6_ESP", "CONFIG_XFRM_USER", "CONFIG_CRYPTO_GCM",
	// conntrack and NAT; SCTP NAT is nf_nat_proto under NF_CT_PROTO_SCTP
	"CONFIG_NF_CONNTRACK", "CONFIG_NF_CONNTRACK_ZONES", "CONFIG_NF_NAT", "CONFIG_NF_NAT_OVS", "CONFIG_NF_CT_PROTO_SCTP",
	// tenancy
	"CONFIG_NET_VRF",
	// vsock
	"CONFIG_VSOCKETS", "CONFIG_VIRTIO_VSOCKETS", "CONFIG_VHOST_VSOCK",
	// hardening
	"CONFIG_MODULE_SIG_FORCE", "CONFIG_SECURITY_LOCKDOWN_LSM", "CONFIG_IMA_APPRAISE", "CONFIG_SCHED_CORE",
	"CONFIG_CRYPTO_FIPS", "CONFIG_CRYPTO_DRBG",
}

func TestPlatformRequiredFragment_CarriesTheRequiredList(t *testing.T) {
	f, err := os.Open(sharedKernelConfig(t, "platform-required.config"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enabled := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if symbol, value, ok := strings.Cut(line, "="); ok && strings.HasPrefix(symbol, "CONFIG_") {
			enabled[symbol] = value == "y" || value == "m"
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range requiredSymbols {
		if !enabled[symbol] {
			t.Errorf("platform-required.config does not enable %s", symbol)
		}
	}
}

func TestPlatformRequiredFragment_PassesItsOwnCheck(t *testing.T) {
	// The fragment, read as a .config, satisfies itself: every line is in
	// a form require-config.sh understands, so a malformed edit fails here
	// rather than an hour into a kernel build.
	fragment := sharedKernelConfig(t, "platform-required.config")
	if code, out := runRequireConfig(t, fragment, fragment); code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
}
