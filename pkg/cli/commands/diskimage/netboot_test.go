package diskimage

import (
	"errors"
	"path/filepath"
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
