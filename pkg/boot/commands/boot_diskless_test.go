package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

func disklessTestArgs() string {
	params := disklessroot.BootParams{
		RootFSURL:  "http://boot.example.com/set/" + disklessroot.RootFSFile,
		VerityURL:  "http://boot.example.com/set/" + disklessroot.VerityFile,
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 32),
		RootFSSize: 4 * disklessroot.BlockSize,
		VeritySize: disklessroot.BlockSize,
	}
	return strings.Join(params.Args(), " ")
}

// withBootFlags sets the boot flags and the kernel command line for one test
// and restores them afterwards.
func withBootFlags(t *testing.T, diskless bool, device, cmdline string) {
	t.Helper()
	savedDiskless, savedDevice, savedPath := bootDiskless, bootDevice, procCmdlinePath
	t.Cleanup(func() { bootDiskless, bootDevice, procCmdlinePath = savedDiskless, savedDevice, savedPath })
	bootDiskless, bootDevice = diskless, device
	procCmdlinePath = filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(procCmdlinePath, []byte(cmdline+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDisklessBootConfigReadsTheSignedCmdline(t *testing.T) {
	withBootFlags(t, true, "", "console=ttyS0 "+disklessTestArgs())
	cfg, err := disklessBootConfig()
	if err != nil {
		t.Fatalf("disklessBootConfig: %v", err)
	}
	if cfg == nil || cfg.Params.RootHash != strings.Repeat("ab", 32) || cfg.Params.DataBlocks() != 4 {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.RootMount != bootRootMount || cfg.WorkDir != bootDisklessWork {
		t.Fatalf("config ignores the mount flags: %+v", cfg)
	}
}

func TestDisklessBootConfigDiskNodeUnlocksLUKSWhateverTheCmdline(t *testing.T) {
	// A disk node whose command line carries diskless parameters, even the
	// boot model, still takes the LUKS path: only --diskless selects it.
	withBootFlags(t, false, "/dev/sda2", disklessTestArgs())
	cfg, err := disklessBootConfig()
	if err != nil || cfg != nil {
		t.Fatalf("disklessBootConfig = %+v, %v, want the LUKS path", cfg, err)
	}
}

func TestDisklessBootConfigErrors(t *testing.T) {
	cases := map[string]struct {
		diskless bool
		device   string
		cmdline  string
		want     string
	}{
		"no device on a disk node":        {device: "", want: "--device flag is required"},
		"diskless and a device":           {diskless: true, device: "/dev/sda2", cmdline: disklessTestArgs(), want: "mutually exclusive"},
		"diskless without the boot model": {diskless: true, cmdline: "root=/dev/sda2", want: "requires " + disklessroot.ParamBootModel},
		"duplicate root hash": {
			diskless: true,
			cmdline:  disklessTestArgs() + " " + disklessroot.ParamRootHash + "=" + strings.Repeat("ef", 32),
			want:     "appears more than once",
		},
		"incomplete parameters": {
			diskless: true,
			cmdline:  disklessroot.ParamBootModel + "=" + disklessroot.BootModel,
			want:     "invalid diskless root configuration",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			withBootFlags(t, tc.diskless, tc.device, tc.cmdline)
			cfg, err := disklessBootConfig()
			if err == nil || cfg != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("disklessBootConfig = %+v, %v, want an error containing %q", cfg, err, tc.want)
			}
		})
	}
}

func TestDisklessBootConfigUnreadableCmdline(t *testing.T) {
	withBootFlags(t, true, "", "")
	procCmdlinePath = filepath.Join(t.TempDir(), "missing")
	_, err := disklessBootConfig()
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disklessBootConfig = %v, want a wrapped not-exist error", err)
	}
}
