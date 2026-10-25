//go:build integration

// Package ipsec is the IPsec transport integration suite (plan §5.2, issue
// #716). It proves the shipped strongSwan build -- the
// trusted-platform-strongswan apks from build/docker/strongswan-builder,
// installed into Alpine (musl) root filesystems exactly as a node installs
// them -- authenticates IKEv2 with an ECDSA key held behind the go-xkms
// PKCS#11 module and installs ESP SAs in the kernel.
//
// Each peer is an Alpine root filesystem in its own network namespace, its
// charon and its module host started by the packaged OpenRC services. charon
// reaches the module through p11-kit-client.so and a p11-kit server that
// hosts it: a Go c-shared library cannot be loaded into a musl process at all
// (docs/sdn/engineering.md, "PKCS#11 on musl"), so each peer's module runs
// in a glibc "module host" root filesystem (Ubuntu 26.04, whose p11-kit
// 0.26.2 matches Alpine's client) that the trusted-platform-p11-host apk
// carries and its service chroots into.
//
// Both architectures are proven: the tests below run natively in the
// devcontainer on amd64, and the same tests, cross-compiled, run natively
// inside an aarch64 VM booted by TestSuiteInARM64VM (vm_test.go) -- qemu-user
// cannot stand in, because it refuses NETLINK_XFRM sockets and charon will not
// start without its kernel IPsec interface.
//
// The suite runs in the devcontainer via `make integration-test-ipsec`; its
// inputs come from the host build through the environment. Missing inputs
// fail the suite -- there are no skip guards.
package ipsec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Environment variables the runner sets (Makefile IPSEC_SUITE_ENV). The
// peer root filesystems exist per architecture: the tests run on the
// architecture they were compiled for (runtime.GOARCH), natively in the
// devcontainer on amd64 and inside an aarch64 VM on arm64 (vm_test.go).
const (
	envRootfsPrefix = "IPSEC_ROOTFS_" // + AMD64 | ARM64
	envWorkDir      = "IPSEC_WORK_DIR"
)

// MissingInputError reports a required suite input that is unset or absent.
type MissingInputError struct {
	Variable string
	Path     string
	Err      error
}

func (e *MissingInputError) Error() string {
	if e.Path == "" {
		return "ipsec suite: " + e.Variable + " is not set (run `make integration-test-ipsec`, which builds the inputs)"
	}
	return "ipsec suite: " + e.Variable + "=" + e.Path + ": " + e.Err.Error()
}

func (e *MissingInputError) Unwrap() error { return e.Err }

// requireFile resolves one file-valued input and fails the test when it is
// unset or missing.
func requireFile(t *testing.T, variable string) string {
	t.Helper()
	value := os.Getenv(variable)
	if value == "" {
		t.Fatal(&MissingInputError{Variable: variable})
	}
	if _, err := os.Stat(value); err != nil {
		t.Fatal(&MissingInputError{Variable: variable, Path: value, Err: err})
	}
	return value
}

// inputs are the suite's resolved inputs for the running architecture.
type inputs struct {
	arch    string
	rootfs  string
	workDir string
}

// requireInputs resolves the inputs for runtime.GOARCH and fails the test
// when any is unset or missing.
func requireInputs(t *testing.T) inputs {
	t.Helper()
	suffix := strings.ToUpper(runtime.GOARCH)
	in := inputs{
		arch:    runtime.GOARCH,
		rootfs:  requireFile(t, envRootfsPrefix+suffix),
		workDir: os.Getenv(envWorkDir),
	}
	if in.workDir == "" {
		in.workDir = filepath.Join(os.TempDir(), "ipsec-integration")
	}
	if err := os.MkdirAll(in.workDir, 0o755); err != nil {
		t.Fatal(&MissingInputError{Variable: envWorkDir, Path: in.workDir, Err: err})
	}
	return in
}
