package diskimagetest

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/iso/isotest"
)

// ErrContainer is what Runner returns for the subcommand it is told to fail.
var ErrContainer = errors.New("diskimagetest: container command failed")

// ErrHostBindMount is what Runner returns for a container that bind-mounts a
// host path, or is started with `run`. A bind mount is resolved on the
// daemon's filesystem, which is not the build's when it runs in a CI job
// container, so builds must move data with `create` and `cp`.
var ErrHostBindMount = errors.New("diskimagetest: container uses a host bind mount")

// ErrUnknownContainer is what Runner returns for a command naming a container
// that was never created.
var ErrUnknownContainer = errors.New("diskimagetest: no such container")

// Runner stands in for the container runtime an image build drives. It
// records every invocation and behaves like a daemon on its own filesystem:
// every container has a private root that `cp` fills and drains. Starting it
// produces what the builder container would: the assembled image for
// `diskimage assemble --output <path>`, and the initramfs and modloop for
// `diskimage netboot-initfs --output <dir>`.
type Runner struct {
	Calls [][]string
	// Fail names a runtime subcommand (build, create, cp, start) that fails.
	Fail string

	containers map[string]*container
}

// container is a created container: its create arguments and its root
// filesystem on the host.
type container struct {
	args []string
	root string
}

// Run implements runner.Runner.
func (r *Runner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.Calls = append(r.Calls, append([]string{name}, args...))
	if len(args) == 0 {
		return nil, nil
	}
	if r.Fail != "" && args[0] == r.Fail {
		return []byte("boom"), ErrContainer
	}
	switch args[0] {
	case "run":
		return nil, ErrHostBindMount
	case "create":
		return nil, r.create(args[1:])
	case "cp":
		if len(args) != 3 {
			return nil, ErrContainer
		}
		return nil, r.cp(args[1], args[2])
	case "start":
		return nil, r.start(args[len(args)-1])
	case "rm":
		return nil, r.remove(args[len(args)-1])
	}
	return nil, nil
}

// create registers a container with an empty root filesystem.
func (r *Runner) create(args []string) error {
	name := flag(args, "--name")
	for i, a := range args {
		if a == "-v" && i+1 < len(args) && strings.HasPrefix(args[i+1], "/") && strings.Contains(args[i+1], ":") {
			return ErrHostBindMount
		}
	}
	root, err := os.MkdirTemp("", "diskimagetest-container-")
	if err != nil {
		return err
	}
	if r.containers == nil {
		r.containers = map[string]*container{}
	}
	r.containers[name] = &container{args: args, root: root}
	return nil
}

// cp copies a directory between the host and a container root. Exactly one
// side names a container as "<name>:<path>".
func (r *Runner) cp(src, dst string) error {
	srcCtr, srcPath, srcIn := r.split(src)
	dstCtr, dstPath, dstIn := r.split(dst)
	if srcIn == dstIn {
		return ErrContainer
	}
	if srcIn {
		return copyTree(filepath.Join(srcCtr.root, srcPath), dstPath)
	}
	return copyTree(srcPath, filepath.Join(dstCtr.root, dstPath))
}

// split resolves "<container>:<path>"; a plain host path reports false.
func (r *Runner) split(ref string) (*container, string, bool) {
	name, path, found := strings.Cut(ref, ":")
	if ctr, ok := r.containers[name]; found && ok {
		return ctr, path, true
	}
	return nil, ref, false
}

// start runs the builder: it writes the files the real command would into the
// container's root, at its --output path.
func (r *Runner) start(name string) error {
	ctr, ok := r.containers[name]
	if !ok {
		return ErrUnknownContainer
	}
	args := ctr.args
	output := filepath.Join(ctr.root, flag(args, "--output"))
	switch {
	case contains(args, "assemble"):
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		return os.WriteFile(output, []byte("image"), 0o644)
	case contains(args, "netboot-initfs"):
		flavour := flag(args, "--flavour")
		initramfs, err := isotest.NetbootInitramfs()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(output, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, "initramfs-"+flavour), initramfs, 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(output, "modloop-"+flavour), []byte("modloop"), 0o644)
	}
	return nil
}

// remove deletes the container and its root.
func (r *Runner) remove(name string) error {
	ctr, ok := r.containers[name]
	if !ok {
		return ErrUnknownContainer
	}
	delete(r.containers, name)
	return os.RemoveAll(ctr.root)
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

// copyTree merges the contents of src into dst, creating dst. `docker cp`
// spells that "src/." — the trailing "/." is dropped here.
func copyTree(src, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
