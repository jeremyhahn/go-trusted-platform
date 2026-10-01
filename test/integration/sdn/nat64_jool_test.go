//go:build integration && nat64vm

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

package sdn

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
)

// The NAT64 driver is proven against a real Jool instance the test creates
// and destroys. These files carry the nat64vm tag: they run inside the
// Alpine VM `make integration-test-nat64` boots (test/integration/nat64),
// whose linux-lts kernel and jool-modules-lts come from one repository
// snapshot. They FAIL rather than skip when the tool or the module is
// missing, because a NAT64 suite that skips itself green is exactly the
// assurance this repository keeps finding to be false.
const nat64TestInstance = "tp-nat64-itest"

// requireJool fails the test when the tool or the module is unavailable.
func requireJool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("jool"); err != nil {
		t.Fatalf("jool tool not found in PATH: the NAT64 VM image must install jool-tools (%v)", err)
	}
	out, err := exec.Command("jool", "instance", "display", "--csv").CombinedOutput()
	if err != nil {
		t.Fatalf("jool cannot reach the kernel module: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// cleanupInstance removes the test instance however the test ended.
func cleanupInstance(t *testing.T, name string) {
	t.Helper()
	_ = exec.Command("jool", "instance", "remove", name).Run()
	t.Cleanup(func() {
		_ = exec.Command("jool", "instance", "remove", name).Run()
	})
}

// testInstanceConfig is the instance every case programs: a range, which
// jool itself cannot take, so the driver must tile it into prefixes.
func testInstanceConfig() nat64.Instance {
	return nat64.Instance{
		Name:  nat64TestInstance,
		Pool6: "64:ff9b::/96",
		Pool4: []nat64.Pool4Range{
			{Addresses: "203.0.113.65-203.0.113.70", PortStart: 61001, PortEnd: 65535},
		},
		Timeouts: nat64.SessionTimeouts{}.WithDefaults(),
	}
}

// pool4Rows reads the kernel's pool4 as "PROTO addr min-max" lines, one
// protocol table at a time (the tool shows TCP's alone otherwise).
func pool4Rows(t *testing.T, name string) []string {
	t.Helper()
	var rows []string
	for _, proto := range []string{"--tcp", "--udp", "--icmp"} {
		out, err := exec.Command("jool", "--instance", name, "pool4", "display", proto, "--csv", "--no-headers").CombinedOutput()
		require.NoError(t, err, "%s", out)
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, ",")
			if len(f) >= 5 {
				rows = append(rows, f[1]+" "+f[2]+" "+f[3]+"-"+f[4])
			}
		}
	}
	return rows
}

// global reads one field of the instance's global configuration.
func global(t *testing.T, name, field string) string {
	t.Helper()
	out, err := exec.Command("jool", "--instance", name, "global", "display", "--csv").CombinedOutput()
	require.NoError(t, err, "%s", out)
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ","); ok && k == field {
			return v
		}
	}
	t.Fatalf("global display carries no %s: %s", field, out)
	return ""
}

// TestJoolDriver_ProgramsARealInstance is the claim the unit tests cannot
// make: the rendered command lines are ones the real jool tool accepts, and
// the instance they build is the one the configuration describes.
func TestJoolDriver_ProgramsARealInstance(t *testing.T) {
	requireJool(t)
	cleanupInstance(t, nat64TestInstance)
	ctx := context.Background()
	driver := nat64.NewJoolDriver()

	created, err := driver.Apply(ctx, testInstanceConfig())
	require.NoError(t, err, "the rendered command lines must be ones the real tool accepts")
	require.True(t, created)

	stats, err := driver.Stats(ctx, nat64TestInstance)
	require.NoError(t, err)
	require.True(t, stats.Present, "the kernel does not hold the instance the driver just created")
	require.NotEmpty(t, stats.ModuleVersion, "the driver could not read the version")

	// .65-.70 is six addresses on three protocols; jool refuses the range
	// spelling, so this proves the prefix tiling end to end.
	rows := pool4Rows(t, nat64TestInstance)
	require.Len(t, rows, 18, "%v", rows)
	for _, proto := range []string{"TCP", "UDP", "ICMP"} {
		for _, addr := range []string{"203.0.113.65", "203.0.113.70"} {
			require.Contains(t, rows, proto+" "+addr+" 61001-65535")
		}
		require.NotContains(t, rows, proto+" 203.0.113.64 61001-65535", "the tiling overran the range")
		require.NotContains(t, rows, proto+" 203.0.113.71 61001-65535", "the tiling overran the range")
	}
	require.Equal(t, "2:04:00", global(t, nat64TestInstance, "tcp-est-timeout"),
		"the RFC 6146 REQ-7 floor, not jool's own 2:00:00 default")
}

// TestJoolDriver_ApplyIsIdempotent: a reconcile converges the instance
// without touching it, so a live translation survives every pass.
func TestJoolDriver_ApplyIsIdempotent(t *testing.T) {
	requireJool(t)
	cleanupInstance(t, nat64TestInstance)
	ctx := context.Background()
	driver := nat64.NewJoolDriver()
	inst := testInstanceConfig()

	_, err := driver.Apply(ctx, inst)
	require.NoError(t, err)
	before := pool4Rows(t, nat64TestInstance)

	for i := 0; i < 3; i++ {
		created, err := driver.Apply(ctx, inst)
		require.NoError(t, err, "reconcile %d failed against an instance that is already there", i)
		require.False(t, created, "reconcile %d recreated a live instance", i)
	}
	require.Equal(t, before, pool4Rows(t, nat64TestInstance))
}

// TestJoolDriver_ConvergesAChangedPool: a narrowed range drops exactly the
// addresses it no longer names, and a moved port range is replaced, on the
// instance in place.
func TestJoolDriver_ConvergesAChangedPool(t *testing.T) {
	requireJool(t)
	cleanupInstance(t, nat64TestInstance)
	ctx := context.Background()
	driver := nat64.NewJoolDriver()
	inst := testInstanceConfig()
	_, err := driver.Apply(ctx, inst)
	require.NoError(t, err)

	inst.Pool4 = []nat64.Pool4Range{{Addresses: "203.0.113.66", PortStart: 62000, PortEnd: 63000}}
	created, err := driver.Apply(ctx, inst)
	require.NoError(t, err)
	require.False(t, created, "a pool change must not recreate the instance")
	require.ElementsMatch(t, []string{
		"TCP 203.0.113.66 62000-63000",
		"UDP 203.0.113.66 62000-63000",
		"ICMP 203.0.113.66 62000-63000",
	}, pool4Rows(t, nat64TestInstance))
}

// TestJoolDriver_RecreatesForANewPrefix: jool refuses to change a NAT64
// instance's pool6, so the driver recreates the instance.
func TestJoolDriver_RecreatesForANewPrefix(t *testing.T) {
	requireJool(t)
	cleanupInstance(t, nat64TestInstance)
	ctx := context.Background()
	driver := nat64.NewJoolDriver()
	inst := testInstanceConfig()
	_, err := driver.Apply(ctx, inst)
	require.NoError(t, err)

	inst.Pool6 = "2001:db8:64::/96"
	created, err := driver.Apply(ctx, inst)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, "2001:db8:64::/96", global(t, nat64TestInstance, "pool6"))
}

// TestJoolDriver_RemoveIsIdempotent proves Stop can run twice and that a
// removed instance really is gone.
func TestJoolDriver_RemoveIsIdempotent(t *testing.T) {
	requireJool(t)
	cleanupInstance(t, nat64TestInstance)
	ctx := context.Background()
	driver := nat64.NewJoolDriver()

	_, err := driver.Apply(ctx, testInstanceConfig())
	require.NoError(t, err)
	require.NoError(t, driver.Remove(ctx, nat64TestInstance))

	stats, err := driver.Stats(ctx, nat64TestInstance)
	require.NoError(t, err)
	require.False(t, stats.Present, "the instance survived its removal")
	require.NoError(t, driver.Remove(ctx, nat64TestInstance),
		"removing an instance that is already gone must not be an error")
}

// TestJoolDriver_RefusesAnInstanceTheModuleWillNotCreate proves the refusal
// path against the real tool: jool caps instance names at 15 characters.
func TestJoolDriver_RefusesAnInstanceTheModuleWillNotCreate(t *testing.T) {
	requireJool(t)
	inst := testInstanceConfig()
	inst.Name = "tp-nat64-name-longer-than-fifteen"
	cleanupInstance(t, inst.Name)

	_, err := nat64.NewJoolDriver().Apply(context.Background(), inst)
	var unavailable *nat64.ErrNAT64ModuleUnavailable
	require.ErrorAs(t, err, &unavailable, "a refusal from the real tool must arrive typed")
	var cmdErr *nat64.CommandError
	require.ErrorAs(t, err, &cmdErr, "the error must name the command an operator can rerun")
	require.Contains(t, strings.Join(cmdErr.Cmd, " "), "instance add")
}
