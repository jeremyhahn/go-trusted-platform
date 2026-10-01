package diskimagetest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/iso/isotest"
)

// ErrContainer is what Runner returns for the subcommand it is told to fail.
var ErrContainer = errors.New("diskimagetest: container command failed")

// Runner stands in for the container runtime an image build drives. It
// records every invocation and produces what the builder container would:
// the assembled image for `diskimage assemble --output /work/<name>`, and the
// initramfs and modloop for `diskimage netboot-initfs`.
type Runner struct {
	Calls [][]string
	// Fail names a runtime subcommand (build, run) that fails.
	Fail string
}

// Run implements runner.Runner.
func (r *Runner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.Calls = append(r.Calls, append([]string{name}, args...))
	if r.Fail != "" && len(args) > 0 && args[0] == r.Fail {
		return []byte("boom"), ErrContainer
	}
	if len(args) == 0 || args[0] != "run" {
		return nil, nil
	}
	switch {
	case contains(args, "assemble"):
		host := mountSource(args, "/work")
		return nil, os.WriteFile(filepath.Join(host, filepath.Base(flag(args, "--output"))), []byte("image"), 0o644)
	case contains(args, "netboot-initfs"):
		host := mountSource(args, "/out")
		flavour := flag(args, "--flavour")
		initramfs, err := isotest.NetbootInitramfs()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(host, "initramfs-"+flavour), initramfs, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(host, "modloop-"+flavour), []byte("modloop"), 0o644); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Joined is every recorded call as one command line each.
func (r *Runner) Joined() []string {
	out := make([]string, 0, len(r.Calls))
	for _, call := range r.Calls {
		out = append(out, strings.Join(call, " "))
	}
	return out
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// flag is the value after name.
func flag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// mountSource is the host side of the -v mount at target.
func mountSource(args []string, target string) string {
	for i, a := range args {
		if a == "-v" && i+1 < len(args) && strings.HasSuffix(args[i+1], ":"+target) {
			return strings.TrimSuffix(args[i+1], ":"+target)
		}
	}
	return ""
}
