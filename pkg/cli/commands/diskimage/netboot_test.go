package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/netboot"
)

func TestSelectSets(t *testing.T) {
	// No names leaves the default to netboot.Config.SetsToBuild.
	none, err := selectSets(nil)
	if err != nil || len(none) != 0 {
		t.Fatalf("default sets = %v, %v", none, err)
	}
	// Named sets come back in the build's own order, whatever the flag's.
	some, err := selectSets([]string{container.MediaSetARM64Virt, container.MediaSetX86_64})
	if err != nil || len(some) != 2 || some[0].Name != container.MediaSetX86_64 || some[1].Name != container.MediaSetARM64Virt {
		t.Fatalf("selected = %v, %v", some, err)
	}
	var unknown ErrUnknownMediaSet
	if _, err := selectSets([]string{"riscv64"}); !errors.As(err, &unknown) || unknown.Name != "riscv64" {
		t.Errorf("unknown set error = %v", err)
	}
}

// A --diskless build without --sets builds only the sets with a diskless
// image: it never asks for x86_64 binaries, and reaches the build itself,
// which here refuses for want of Secure Boot before any container runs.
func TestRunNetboot_DisklessDefaultSetsLeaveOutX86(t *testing.T) {
	arm64 := t.TempDir()
	if err := os.WriteFile(filepath.Join(arm64, "platformd"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	flags := &netbootFlags{
		diskless:         true,
		sourceDateEpoch:  1,
		x86BinariesDir:   filepath.Join(t.TempDir(), "empty"),
		arm64BinariesDir: arm64,
		output:           filepath.Join(t.TempDir(), "media"),
	}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	err := runNetboot(&cli.CommonFlags{}, flags)
	var notFound ErrBinariesNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("a default diskless build asked for the %s binaries: %v", notFound.Dir, err)
	}
	var failed ErrBuildFailed
	if !errors.As(err, &failed) || !strings.Contains(failed.Reason, "Secure Boot") {
		t.Errorf("error = %v, want the build's Secure Boot refusal", err)
	}
}

func TestRunNetboot_FailsBeforeBuilding(t *testing.T) {
	var unknown ErrUnknownMediaSet
	if err := runNetboot(&cli.CommonFlags{}, &netbootFlags{sets: []string{"nope"}}); !errors.As(err, &unknown) {
		t.Errorf("unknown set error = %v", err)
	}
	var notFound ErrBinariesNotFound
	flags := &netbootFlags{sets: []string{container.MediaSetX86_64}, x86BinariesDir: filepath.Join(t.TempDir(), "empty"), sourceDateEpoch: -1}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	if err := runNetboot(&cli.CommonFlags{}, flags); !errors.As(err, &notFound) {
		t.Errorf("missing binaries error = %v", err)
	}
	// A diskless build without a timestamp would not be reproducible.
	t.Setenv("SOURCE_DATE_EPOCH", "")
	var epoch ErrSourceDateEpoch
	flags = &netbootFlags{sets: []string{container.MediaSetARM64Virt}, diskless: true, sourceDateEpoch: -1}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	if err := runNetboot(&cli.CommonFlags{}, flags); !errors.As(err, &epoch) {
		t.Errorf("missing SOURCE_DATE_EPOCH error = %v", err)
	}
}

func TestRunDisklessRoot_Fails(t *testing.T) {
	var required ErrConfigRequired
	if err := runDisklessRoot(context.Background(), &disklessRootFlags{}); !errors.As(err, &required) {
		t.Errorf("no configuration error = %v", err)
	}
	// A configuration that loads but cannot build (no salt, no output)
	// fails the build, never prints a root.
	config := filepath.Join(t.TempDir(), "installer.yaml")
	if err := os.WriteFile(config, []byte("disk:\n  device: /dev/vda\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var failed ErrBuildFailed
	flags := &disklessRootFlags{}
	flags.config = config
	if err := runDisklessRoot(context.Background(), flags); !errors.As(err, &failed) {
		t.Errorf("invalid build error = %v", err)
	}
}

func TestResolveSourceDateEpoch(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag int64
		env  string
		want int64
	}{
		{"the flag wins", 42, "7", 42},
		{"zero is a valid flag", 0, "7", 0},
		{"the environment when no flag", -1, "1700000000", 1700000000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSourceDateEpoch(tc.flag, tc.env)
			if err != nil || got != tc.want {
				t.Errorf("resolveSourceDateEpoch(%d, %q) = %d, %v; want %d", tc.flag, tc.env, got, err, tc.want)
			}
		})
	}
	for _, env := range []string{"", "yesterday", "-5"} {
		var epoch ErrSourceDateEpoch
		if _, err := resolveSourceDateEpoch(-1, env); !errors.As(err, &epoch) || epoch.Value != env {
			t.Errorf("resolveSourceDateEpoch(-1, %q) error = %v", env, err)
		}
	}
}

func TestHTTPBootConfig(t *testing.T) {
	off, err := (&netbootFlags{sourceDateEpoch: -1}).httpBootConfig()
	if err != nil || off != nil {
		t.Fatalf("no --fleet-key = %v, %v; want no HTTP boot", off, err)
	}
	on, err := (&netbootFlags{fleetKey: "kms://rpi/fleet", fleetCert: "kms://rpi/cert", sourceDateEpoch: 1790856000, targetSoC: "2712"}).httpBootConfig()
	if err != nil {
		t.Fatal(err)
	}
	if on.FleetKey != "kms://rpi/fleet" || on.FleetCert != "kms://rpi/cert" || on.Timestamp.Unix() != 1790856000 || on.TargetSoC != "2712" {
		t.Errorf("config = %+v", on)
	}
	now, err := (&netbootFlags{fleetKey: "kms://rpi/fleet", sourceDateEpoch: -1}).httpBootConfig()
	if err != nil || !now.Timestamp.IsZero() || now.TargetSoC != "" {
		t.Errorf("default timestamp/target-soc = %v, %v; want zero timestamp and omitted target-soc", now, err)
	}
	epoch, err := (&netbootFlags{fleetKey: "kms://rpi/fleet", sourceDateEpoch: 0}).httpBootConfig()
	if err != nil || epoch.Timestamp.IsZero() || epoch.Timestamp.Unix() != 0 {
		t.Errorf("--source-date-epoch 0 = %v, %v; want the epoch itself", epoch, err)
	}
}

func TestHTTPBootConfig_FlagsNeedTheFleetKey(t *testing.T) {
	for flag, flags := range map[string]*netbootFlags{
		"fleet-cert":        {fleetCert: "kms://rpi/cert", sourceDateEpoch: -1},
		"source-date-epoch": {sourceDateEpoch: 1},
		"target-soc":        {targetSoC: "2712", sourceDateEpoch: -1},
	} {
		var flagErr ErrHTTPBootFlags
		if _, err := flags.httpBootConfig(); !errors.As(err, &flagErr) || flagErr.Flag != flag {
			t.Errorf("--%s without --fleet-key = %v", flag, err)
		}
	}
	flags := &netbootFlags{fleetCert: "kms://rpi/cert", sourceDateEpoch: -1}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	var flagErr ErrHTTPBootFlags
	if err := runNetboot(&cli.CommonFlags{}, flags); !errors.As(err, &flagErr) {
		t.Errorf("runNetboot = %v, want the flag error before any build", err)
	}
}

// --source-date-epoch also times the diskless root, so with --diskless it
// needs no fleet key.
func TestHTTPBootConfig_DisklessOwnsTheEpoch(t *testing.T) {
	got, err := (&netbootFlags{diskless: true, sourceDateEpoch: 1}).httpBootConfig()
	if err != nil || got != nil {
		t.Errorf("--diskless --source-date-epoch = %v, %v; want no HTTP boot and no error", got, err)
	}
}

func TestHTTPBootSummary(t *testing.T) {
	hash := [32]byte{0xab}
	out := httpBootSummary(&netboot.Result{
		Dir:          "bin/netboot-media",
		HTTPBoot:     &netboot.HTTPBootFiles{KeyHash: hash, ImageSize: 4096},
		HTTPBootPath: "data/http-boot",
	})
	for _, want := range []string{"ab00000000", "IRREVERSIBLE", "HTTP_PATH=data/http-boot", "SIGNED_BOOT=1", "4096"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}
