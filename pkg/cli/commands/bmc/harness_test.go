// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package bmc

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// fn wrote together with fn's error. The commands in this package print
// straight to os.Stdout, so this is the only way to assert their output.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	return captureFile(t, &os.Stdout, fn)
}

// captureStderr is captureStdout for os.Stderr, where the console command
// reports progress and warnings.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	return captureFile(t, &os.Stderr, fn)
}

// captureFile swaps *target for a pipe while fn runs and returns what fn
// wrote to it.
func captureFile(t *testing.T, target **os.File, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	type readResult struct {
		data []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		data, readErr := io.ReadAll(r)
		done <- readResult{data: data, err: readErr}
	}()

	orig := *target
	*target = w
	runErr := func() error {
		defer func() { *target = orig }()
		return fn()
	}()

	require.NoError(t, w.Close())
	res := <-done
	require.NoError(t, res.err)
	require.NoError(t, r.Close())
	return string(res.data), runErr
}

// withStdin replaces os.Stdin with a pipe holding input for the duration of
// the test. A pipe is never a terminal, so isTerminal reports false.
func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		require.NoError(t, r.Close())
	})
}

// runBMC executes the bmc root command with args and returns its stdout.
func runBMC(t *testing.T, getFlags func() *cli.CommonFlags, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(getFlags)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return captureStdout(t, cmd.Execute)
}

// standaloneIPMIArgs are the standalone flags every direct-to-BMC test uses.
// An explicit protocol keeps protocol detection (a network probe) out of the
// unit tests.
var standaloneIPMIArgs = []string{
	"--bmc-host", "192.0.2.10",
	"--bmc-user", "admin",
	"--bmc-pass", "secret",
	"--bmc-protocol", "ipmi",
}

// withArgs returns a new slice of base followed by extra, never aliasing base.
func withArgs(base []string, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base...)
	return append(out, extra...)
}
