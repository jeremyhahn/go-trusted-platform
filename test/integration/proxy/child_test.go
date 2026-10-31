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

//go:build integration

package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
)

// hardenedThreadsEnv turns a re-executed suite binary into a hardened child:
// it pins goroutines to OS threads of their own, enters the proxy process's
// hardened state as the account in the variable ("<uid>:<gid>"), and prints
// what every thread holds (#657).
const hardenedThreadsEnv = "GATEWAYD_PROXY_TEST_HARDENED_THREADS"

// hardenedPinnedThreads is how many goroutines the hardened child locks to OS
// threads of their own before the drop, so the process holds threads the
// dropping goroutine never ran on.
const hardenedPinnedThreads = 4

// hardenedFields are the /proc/<pid>/task/<tid>/status fields the child
// reports for each thread.
var hardenedFields = []string{"Uid", "Gid", "Groups", "NoNewPrivs", "Seccomp", "CapPrm", "CapEff", "CapBnd"}

func TestMain(m *testing.M) {
	if account, child := os.LookupEnv(hardenedThreadsEnv); child {
		os.Exit(reportHardenedThreads(account))
	}
	os.Exit(m.Run())
}

// reportHardenedThreads is the hardened child. It prints a JSON object from
// each thread id to that thread's hardenedFields.
func reportHardenedThreads(account string) int {
	uidText, gidText, _ := strings.Cut(account, ":")
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "uid:", err)
		return 1
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gid:", err)
		return 1
	}
	def, err := process.DefinitionByName("proxy")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	release := make(chan struct{})
	pinned := make(chan struct{})
	for range hardenedPinnedThreads {
		go func() {
			runtime.LockOSThread()
			pinned <- struct{}{}
			<-release
		}()
	}
	for range hardenedPinnedThreads {
		<-pinned
	}
	defer close(release)

	if err := process.EnterHardened(def, uint32(uid), uint32(gid)); err != nil {
		fmt.Fprintln(os.Stderr, "enter hardened:", err)
		return 1
	}
	threads, err := threadFields()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(threads); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// threadFields reads hardenedFields for every thread of this process, with
// each value's whitespace collapsed to single spaces.
func threadFields() (map[string]map[string]string, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	threads := make(map[string]map[string]string, len(tasks))
	for _, task := range tasks {
		status, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "status"))
		if err != nil {
			return nil, err
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(status), "\n") {
			name, value, _ := strings.Cut(line, ":")
			fields[name] = strings.Join(strings.Fields(value), " ")
		}
		threads[task.Name()] = map[string]string{}
		for _, field := range hardenedFields {
			threads[task.Name()][field] = fields[field]
		}
	}
	return threads, nil
}

// TestEnterHardened_EveryThreadHoldsTheProxyCredentials runs the proxy
// process's drop in a real child with threads pinned beside the dropping one,
// and requires every thread to hold the service account, no_new_privs, the
// seccomp filter and only the proxy class's capability.
func TestEnterHardened_EveryThreadHoldsTheProxyCredentials(t *testing.T) {
	uid, gid := serviceAccount(t)
	def, err := process.DefinitionByName("proxy")
	if err != nil {
		t.Fatalf("proxy definition: %v", err)
	}

	cmd := exec.Command(os.Args[0]) // #nosec G204 -- the suite binary re-executes itself
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d:%d", hardenedThreadsEnv, uid, gid))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hardened child: %v: %s", err, stderr.String())
	}
	var threads map[string]map[string]string
	if err := json.Unmarshal(out, &threads); err != nil {
		t.Fatalf("hardened child output %q: %v", out, err)
	}
	if len(threads) <= hardenedPinnedThreads {
		t.Fatalf("hardened child reported %d threads, want more than the %d pinned", len(threads), hardenedPinnedThreads)
	}

	var mask uint64
	for _, capability := range def.Capabilities {
		mask |= 1 << capability
	}
	caps := fmt.Sprintf("%016x", mask)
	u, g := strconv.Itoa(uid), strconv.Itoa(gid)
	want := map[string]string{
		"Uid":        strings.Join([]string{u, u, u, u}, " "),
		"Gid":        strings.Join([]string{g, g, g, g}, " "),
		"Groups":     g,
		"NoNewPrivs": "1",
		"Seccomp":    "2",
		"CapPrm":     caps,
		"CapEff":     caps,
		"CapBnd":     caps,
	}
	for tid, fields := range threads {
		if !reflect.DeepEqual(fields, want) {
			t.Errorf("thread %s holds %v, want %v", tid, fields, want)
		}
	}
}
