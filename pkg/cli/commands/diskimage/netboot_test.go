package diskimage

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/netboot"
)

func TestSelectSets(t *testing.T) {
	all, err := selectSets(nil)
	if err != nil || len(all) != len(netboot.DefaultSets) {
		t.Fatalf("default sets = %v, %v", all, err)
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

func TestRunNetboot_FailsBeforeBuilding(t *testing.T) {
	var unknown ErrUnknownMediaSet
	if err := runNetboot(&cli.CommonFlags{}, &netbootFlags{sets: []string{"nope"}}); !errors.As(err, &unknown) {
		t.Errorf("unknown set error = %v", err)
	}
	var notFound ErrBinariesNotFound
	flags := &netbootFlags{sets: []string{container.MediaSetX86_64}, x86BinariesDir: filepath.Join(t.TempDir(), "empty")}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	if err := runNetboot(&cli.CommonFlags{}, flags); !errors.As(err, &notFound) {
		t.Errorf("missing binaries error = %v", err)
	}
}

func TestHTTPBootConfig(t *testing.T) {
	off, err := (&netbootFlags{}).httpBootConfig()
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
	now, err := (&netbootFlags{fleetKey: "kms://rpi/fleet"}).httpBootConfig()
	if err != nil || !now.Timestamp.IsZero() || now.TargetSoC != "" {
		t.Errorf("default timestamp/target-soc = %v, %v; want zero timestamp and omitted target-soc", now, err)
	}
}

func TestHTTPBootConfig_FlagsNeedTheFleetKey(t *testing.T) {
	for flag, flags := range map[string]*netbootFlags{
		"fleet-cert":        {fleetCert: "kms://rpi/cert"},
		"source-date-epoch": {sourceDateEpoch: 1},
		"target-soc":        {targetSoC: "2712"},
	} {
		var flagErr ErrHTTPBootFlags
		if _, err := flags.httpBootConfig(); !errors.As(err, &flagErr) || flagErr.Flag != flag {
			t.Errorf("--%s without --fleet-key = %v", flag, err)
		}
	}
	flags := &netbootFlags{fleetCert: "kms://rpi/cert"}
	flags.alpineVersion, flags.workDir = "3.22.2", t.TempDir()
	var flagErr ErrHTTPBootFlags
	if err := runNetboot(&cli.CommonFlags{}, flags); !errors.As(err, &flagErr) {
		t.Errorf("runNetboot = %v, want the flag error before any build", err)
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
