package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Copy maps a host directory to a container directory.
type Copy struct {
	Host      string
	Container string
}

// Container is one run of a builder container without a host bind mount.
//
// A bind mount is resolved by the container daemon on ITS filesystem. When the
// build runs inside a CI job container the daemon is the host's and the
// checkout is not on it: inputs arrive as an empty directory and outputs never
// reach the caller. Data therefore moves with `cp`, which streams through the
// client and behaves the same on a developer host, in a job container and
// against a remote daemon. build/docker/run-builder.sh is the same mechanism
// for the Makefile builders.
type Container struct {
	// Image is the builder image.
	Image string
	// CreateArgs are `create` flags: environment (-e), --platform,
	// --privileged, and volumes that name a container path only (-v /work) or
	// a named volume (-v cache:/build/src), never a host path.
	CreateArgs []string
	// Command is the command line after the image; empty runs the image's
	// entrypoint.
	Command []string
	// In are host directories copied into the container before it starts. A
	// missing container directory is created.
	In []Copy
	// Out are container directories copied to the host after the container
	// exited successfully; each must exist when it exits. A failed run copies
	// nothing out.
	Out []Copy
}

// Run creates the container, copies the inputs in, runs it to completion,
// copies the outputs out and removes it, always. runtime is the container
// runtime binary (docker or podman).
func (c Container) Run(ctx context.Context, run Runner, runtime string) (err error) {
	name, err := containerName()
	if err != nil {
		return &ContainerError{Step: "naming the container", Err: err}
	}
	create := append([]string{"create", "--name", name}, c.CreateArgs...)
	create = append(create, c.Image)
	create = append(create, c.Command...)
	if _, err := run(ctx, runtime, create...); err != nil {
		return &ContainerError{Step: "creating the container", Err: err}
	}
	defer func() {
		// The caller's cancellation must not leave the container behind.
		if _, rmErr := run(context.WithoutCancel(ctx), runtime, "rm", "-f", "-v", name); rmErr != nil && err == nil {
			err = &ContainerError{Step: "removing the container", Err: rmErr}
		}
	}()

	for _, in := range c.In {
		if _, err := run(ctx, runtime, "cp", dirContents(in.Host), name+":"+in.Container); err != nil {
			return &ContainerError{Step: "copying " + in.Host + " in", Err: err}
		}
	}
	if _, err := run(ctx, runtime, "start", "-a", name); err != nil {
		return &ContainerError{Step: "running the container", Err: err}
	}
	for _, out := range c.Out {
		if err := os.MkdirAll(out.Host, 0o755); err != nil {
			return &ContainerError{Step: "creating " + out.Host, Err: err}
		}
		if _, err := run(ctx, runtime, "cp", name+":"+dirContents(out.Container), out.Host); err != nil {
			return &ContainerError{Step: "copying " + out.Container + " out", Err: err}
		}
	}
	return nil
}

// dirContents is the `cp` source form that copies a directory's contents
// rather than the directory itself.
func dirContents(dir string) string {
	return filepath.Clean(dir) + string(filepath.Separator) + "."
}

// containerName is a unique name, so concurrent runs never collide and the
// container can be addressed without parsing `create`'s output.
func containerName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "builder-" + hex.EncodeToString(b), nil
}

// ContainerError reports the step of a container run that failed.
type ContainerError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *ContainerError) Error() string { return "runner: " + e.Step + ": " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *ContainerError) Unwrap() error { return e.Err }
