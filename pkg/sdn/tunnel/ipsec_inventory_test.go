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

package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

// recordedInventory is an inventory that already records each anchor, as a
// manager that installed them would have left it, with no carrier recorded.
func recordedInventory(t *testing.T, anchors ...*vnl.XfrmState) Option {
	t.Helper()
	inv := &ipsecInventory{path: filepath.Join(t.TempDir(), "ipsec-installed.json")}
	for _, anchor := range anchors {
		require.NoError(t, inv.add(anchor, anchor, ""))
	}
	return WithIPsecInventory(inv.path)
}

// corruptInventory is an inventory path whose file does not decode.
func corruptInventory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), ipsecInventoryMode))
	return path
}

// unwritableInventory makes every later write of the inventory at path fail,
// even for root: its temporary file's name is taken by a directory.
func unwritableInventory(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Mkdir(path+".tmp", 0o700))
}

// secondIPsecConfig is a second IPsec tunnel beside ipsecConfig, on its own
// remote and SPIs and the same key references, so keysFor(ipsecConfig())
// serves both. Its record keeps the inventory non-empty when the first
// pair's goes, so dropping that record rewrites the file.
func secondIPsecConfig() TunnelConfig {
	cfg := ipsecConfig()
	cfg.Name, cfg.Remote, cfg.TunnelIP = "gre-sec", "198.51.100.101", "10.255.0.5/30"
	ipsec := *cfg.IPsec
	ipsec.SPIOut, ipsec.SPIIn = 0x2001, 0x2002
	cfg.IPsec = &ipsec
	return cfg
}

func TestIPsecInventory_RecordsAndDropsPairs(t *testing.T) {
	cfg := ipsecConfig()
	out, in := ipsecStates(cfg, nil, nil)
	moved := cfg
	moved.Local = "198.51.100.37"
	movedOut, movedIn := ipsecStates(moved, nil, nil)
	inv := &ipsecInventory{path: filepath.Join(t.TempDir(), "state", "ipsec-installed.json")}

	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Empty(t, recorded, "a missing file records nothing")

	require.NoError(t, inv.add(out, in, cfg.Name))
	require.NoError(t, inv.add(out, in, cfg.Name), "recording a pair twice is a no-op")
	movedPolOut, movedPolIn := ipsecPolicies(moved)
	require.NoError(t, inv.add(movedOut, movedIn, "gre-moved", movedPolOut, movedPolIn))
	recorded, err = inv.load()
	require.NoError(t, err)
	assert.Equal(t, map[ipsecPairRecord]*ipsecInventoryEntry{
		recordOf(out): {ipsecPairRecord: recordOf(out), Carriers: []string{cfg.Name},
			SAs: []ipsecSARecord{saRecordOf(out), saRecordOf(in)}},
		recordOf(movedOut): {ipsecPairRecord: recordOf(movedOut), Carriers: []string{"gre-moved"},
			SAs:      []ipsecSARecord{saRecordOf(movedOut), saRecordOf(movedIn)},
			Policies: []ipsecPolicyRecord{policyRecordOf(movedPolIn), policyRecordOf(movedPolOut)}},
	}, recorded, "a pair is its request id and both endpoints, recorded with its SAs, policies and carrier")

	// A later install under the same pair, a carrier of another name and a
	// new inbound SPI, adds to the record and drops nothing from it.
	rekeyedIn := *movedIn
	rekeyedIn.Spi = movedIn.Spi + 1
	renamed := moved
	renamed.Type = TunnelTypeIPIP
	ipipOut, ipipIn := ipsecPolicies(renamed)
	require.NoError(t, inv.add(movedOut, &rekeyedIn, "ipip-renamed", ipipOut, ipipIn))
	recorded, err = inv.load()
	require.NoError(t, err)
	entry := recorded[recordOf(movedOut)]
	require.NotNil(t, entry)
	assert.ElementsMatch(t, []ipsecPolicyRecord{policyRecordOf(movedPolOut), policyRecordOf(movedPolIn),
		policyRecordOf(ipipOut), policyRecordOf(ipipIn)}, entry.Policies, "the replaced carrier's policies stay recorded")
	assert.Equal(t, []string{"gre-moved", "ipip-renamed"}, entry.Carriers, "the replaced carrier stays recorded")
	assert.ElementsMatch(t, []ipsecSARecord{saRecordOf(movedOut), saRecordOf(movedIn), saRecordOf(&rekeyedIn)}, entry.SAs,
		"the obsolete inbound SA stays recorded")
	info, err := os.Stat(inv.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(ipsecInventoryMode), info.Mode().Perm())

	require.NoError(t, inv.forget(movedOut, []ipsecSARecord{saRecordOf(movedIn)},
		[]ipsecPolicyRecord{policyRecordOf(movedPolOut), policyRecordOf(movedPolIn)}, []string{"gre-moved"}))
	require.NoError(t, inv.forget(movedOut, nil, nil, nil), "forgetting nothing is a no-op")
	require.NoError(t, inv.forget(&rekeyedIn, []ipsecSARecord{saRecordOf(out)}, nil, nil), "forgetting under an unrecorded pair is a no-op")
	recorded, err = inv.load()
	require.NoError(t, err)
	entry = recorded[recordOf(movedOut)]
	require.NotNil(t, entry, "forgetting keeps the pair")
	assert.Equal(t, []string{"ipip-renamed"}, entry.Carriers)
	assert.ElementsMatch(t, []ipsecPolicyRecord{policyRecordOf(ipipOut), policyRecordOf(ipipIn)}, entry.Policies)
	assert.ElementsMatch(t, []ipsecSARecord{saRecordOf(movedOut), saRecordOf(&rekeyedIn)}, entry.SAs)

	require.NoError(t, inv.remove(out))
	require.NoError(t, inv.remove(out), "dropping an unrecorded pair is a no-op")
	recorded, err = inv.load()
	require.NoError(t, err)
	assert.Len(t, recorded, 1)
	assert.Contains(t, recorded, recordOf(movedOut))
}

func TestIPsecInventory_WithoutAPathRecordsNothing(t *testing.T) {
	m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithIPsecInventory(""))
	require.Nil(t, m.inventory)
	out, _ := ipsecStates(ipsecConfig(), nil, nil)

	recorded, err := m.inventory.load()
	require.NoError(t, err)
	assert.Empty(t, recorded)
	assert.NoError(t, m.inventory.add(out, out, "gre-test"))
	assert.NoError(t, m.inventory.forget(out, []ipsecSARecord{saRecordOf(out)}, nil, nil))
	assert.NoError(t, m.inventory.remove(out))
}

func TestIPsecInventory_Errors(t *testing.T) {
	out, _ := ipsecStates(ipsecConfig(), nil, nil)
	cases := map[string]struct {
		inventory func(t *testing.T) *ipsecInventory
		op        string
	}{
		"decode": {
			inventory: func(t *testing.T) *ipsecInventory { return &ipsecInventory{path: corruptInventory(t)} },
			op:        "decode",
		},
		"read": {
			inventory: func(t *testing.T) *ipsecInventory { return &ipsecInventory{path: t.TempDir()} },
			op:        "read",
		},
		"write": {
			inventory: func(t *testing.T) *ipsecInventory {
				inv := &ipsecInventory{path: filepath.Join(t.TempDir(), "ipsec-installed.json")}
				unwritableInventory(t, inv.path)
				return inv
			},
			op: "write",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.inventory(t).add(out, out, "gre-test")

			var invErr *ErrIPsecInventory
			require.ErrorAs(t, err, &invErr)
			assert.Equal(t, tc.op, invErr.Op)
			assert.Contains(t, err.Error(), "ipsec inventory ")
			assert.NotNil(t, invErr.Unwrap())
		})
	}
}

// A temporary file a crashed write left behind at a wider mode does not pass
// that mode on to the record renamed over the inventory.
func TestIPsecInventory_AStaleTemporaryFileDoesNotWidenTheRecord(t *testing.T) {
	out, in := ipsecStates(ipsecConfig(), nil, nil)
	inv := &ipsecInventory{path: filepath.Join(t.TempDir(), "ipsec-installed.json")}
	require.NoError(t, os.WriteFile(inv.path+".tmp", []byte("partial"), 0o644))
	require.NoError(t, os.Chmod(inv.path+".tmp", 0o644))

	require.NoError(t, inv.add(out, in, "gre-test"))

	info, err := os.Stat(inv.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(ipsecInventoryMode), info.Mode().Perm())
	recorded, err := inv.load()
	require.NoError(t, err)
	assert.Contains(t, recorded, recordOf(out), "the stale content is replaced, not appended to")
}

func TestFillFile_ReportsAWriteItCannotMake(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro")
	require.NoError(t, os.WriteFile(path, nil, ipsecInventoryMode))
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	assert.Error(t, fillFile(f, []byte("data"), ipsecInventoryMode), "a read-only file cannot be written")
}

// A pair is recorded before its SAs go in: an inventory that cannot be
// written fails the ensure before any SA is installed.
func TestManager_EnsureTunnel_IPsecInstallsNothingItCannotRecord(t *testing.T) {
	cfg := ipsecConfig()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	unwritableInventory(t, path)
	mock := newMockNetlinkOps()
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))

	err := m.EnsureTunnel(context.Background(), cfg)

	var createErr *ErrTunnelCreateFailed
	require.ErrorAs(t, err, &createErr)
	var invErr *ErrIPsecInventory
	require.ErrorAs(t, err, &invErr)
	assert.Empty(t, mock.xfrmStates, "no SA is installed unrecorded")
}

func TestManager_EnsureTunnel_IPsecRetireFailsOnAnUnreadableInventory(t *testing.T) {
	old := ipsecConfig()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	mock := newMockNetlinkOps()
	killed := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(old)), WithIPsecInventory(path))
	require.NoError(t, killed.EnsureTunnel(context.Background(), old))
	require.NoError(t, os.WriteFile(path, []byte("not json"), ipsecInventoryMode))
	cfg := old
	cfg.Local = "198.51.100.37"
	relaunched := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))

	err := relaunched.EnsureTunnel(context.Background(), cfg)

	var sweepErr *ErrIPsecSweepFailed
	require.ErrorAs(t, err, &sweepErr)
	assert.Equal(t, "read inventory", sweepErr.Op)
	assert.Len(t, mock.xfrmStates, 2, "the old pair is left for the next attempt")
}

func TestManager_SweepIPsec_InventoryErrors(t *testing.T) {
	cfg := ipsecConfig()
	t.Run("read inventory", func(t *testing.T) {
		m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithIPsecInventory(corruptInventory(t)))

		var sweepErr *ErrIPsecSweepFailed
		require.ErrorAs(t, m.SweepIPsec(), &sweepErr)
		assert.Equal(t, "read inventory", sweepErr.Op)
	})
	t.Run("update inventory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ipsec-installed.json")
		mock := newMockNetlinkOps()
		killed := newManagerWithOps(testLogger(), mock, WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))
		require.NoError(t, killed.EnsureTunnel(context.Background(), cfg))
		require.NoError(t, killed.EnsureTunnel(context.Background(), secondIPsecConfig()))
		require.Len(t, mock.xfrmStates, 4)
		unwritableInventory(t, path)
		relaunched := newManagerWithOps(testLogger(), mock, WithIPsecInventory(path))

		var sweepErr *ErrIPsecSweepFailed
		require.ErrorAs(t, relaunched.SweepIPsec(), &sweepErr)
		assert.Equal(t, "update inventory", sweepErr.Op)
		assert.Len(t, mock.xfrmStates, 2, "a pair is swept even when its record cannot be dropped")
		recorded, err := (&ipsecInventory{path: path}).load()
		require.NoError(t, err)
		assert.Len(t, recorded, 2, "a record that cannot be dropped stays for the next sweep")
	})
}

func TestManager_RemoveTunnel_IPsecDropsTheRecordWithTheAnchor(t *testing.T) {
	cfg := ipsecConfig()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))

	recorded, err := (&ipsecInventory{path: path}).load()
	require.NoError(t, err)
	assert.Empty(t, recorded, "a removed pair is no longer recorded")
}

func TestManager_RemoveTunnel_IPsecReportsARecordItCannotDrop(t *testing.T) {
	cfg := ipsecConfig()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	require.NoError(t, m.EnsureTunnel(context.Background(), secondIPsecConfig()))
	unwritableInventory(t, path)

	err := m.RemoveTunnel(context.Background(), cfg.Name)

	var removeErr *ErrTunnelRemoveFailed
	require.ErrorAs(t, err, &removeErr)
	var invErr *ErrIPsecInventory
	assert.ErrorAs(t, err, &invErr)
}

func TestIPsecInventory_StoreRemovesAnEmptiedRecord(t *testing.T) {
	cfg := ipsecConfig()
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithKeyProvider(keysFor(cfg)), WithIPsecInventory(path))
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))
	require.FileExists(t, path)

	require.NoError(t, m.RemoveTunnel(context.Background(), cfg.Name))

	assert.NoFileExists(t, path, "an inventory with no pair left is removed, so its absence means nothing is recorded")
	inv := &ipsecInventory{path: path}
	require.NoError(t, inv.store(map[ipsecPairRecord]*ipsecInventoryEntry{}), "emptying an absent record is not an error")
}

func TestIPsecInventory_StoreReportsAnEmptiedRecordItCannotRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-installed.json")
	require.NoError(t, os.MkdirAll(filepath.Join(path, "occupied"), 0o700))
	inv := &ipsecInventory{path: path}

	err := inv.store(map[ipsecPairRecord]*ipsecInventoryEntry{})

	var invErr *ErrIPsecInventory
	require.ErrorAs(t, err, &invErr)
	assert.Equal(t, "remove", invErr.Op)
}
