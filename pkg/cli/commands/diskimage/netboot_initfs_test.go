package diskimage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestNetbootInitfsCommand_RefusesAMissingInput runs the hidden in-container
// step through the command tree: every one of its four inputs is required,
// and a refusal comes before anything is installed or written.
func TestNetbootInitfsCommand_RefusesAMissingInput(t *testing.T) {
	for _, missing := range []string{"modules", "release", "flavour", "output"} {
		t.Run(missing, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "out")
			inputs := map[string]string{
				"modules": filepath.Join(dir, "modules.tar.gz"),
				"release": "6.12.1-0-lts",
				"flavour": "lts",
				"output":  output,
			}
			args := []string{"netboot-initfs"}
			for flag, value := range inputs {
				if flag != missing {
					args = append(args, "--"+flag, value)
				}
			}
			cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
			cmd.SetArgs(args)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true

			err := cmd.Execute()
			var build ErrBuildFailed
			if !errors.As(err, &build) || !strings.Contains(build.Reason, "diskimage: netboot initfs:") {
				t.Fatalf("err = %v, want the netboot initfs input refusal", err)
			}
			if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("output directory created on a refusal: %v", statErr)
			}
		})
	}
}
