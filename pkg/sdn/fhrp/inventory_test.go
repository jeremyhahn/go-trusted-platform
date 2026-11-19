package fhrp

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

// linkProgrammer is a Programmer whose DeleteAddress fails with the link
// lookup error set for the interface.
type linkProgrammer struct {
	lookup  map[string]error
	deleted []netip.Prefix
}

func (p *linkProgrammer) AddAddress(string, netip.Prefix, net.HardwareAddr) error { return nil }
func (p *linkProgrammer) DeleteAddress(iface string, prefix netip.Prefix, _ net.HardwareAddr) error {
	if err := p.lookup[iface]; err != nil {
		return err
	}
	p.deleted = append(p.deleted, prefix)
	return nil
}
func (p *linkProgrammer) Announce(string, netip.Addr, net.HardwareAddr) error { return nil }

// TestInventorySweepForgetsVIPOnMissingInterface: a recorded VIP whose
// interface no longer exists went with it; the sweep forgets the entry
// rather than failing every start on it. Any other link lookup failure
// keeps the entry and fails the sweep.
func TestInventorySweepForgetsVIPOnMissingInterface(t *testing.T) {
	gone := netip.MustParsePrefix("192.0.2.1/24")
	failing := netip.MustParsePrefix("198.51.100.1/24")
	deleted := netip.MustParsePrefix("203.0.113.1/24")
	inv := NewInventory(filepath.Join(t.TempDir(), VIPInventoryFile))
	for _, e := range []InventoryEntry{{"gone0", 10, gone}, {"eth1", 20, failing}, {"eth2", 30, deleted}} {
		if err := inv.Record(e.Interface, e.VRID, e.Prefix); err != nil {
			t.Fatal(err)
		}
	}
	prog := &linkProgrammer{lookup: map[string]error{
		"gone0": vnl.LinkNotFoundError{},
		"eth1":  &ErrSpeakerNotRunning{},
	}}

	err := inv.Sweep(prog, func(InventoryEntry) bool { return false })
	var addrErr *ErrAddressOperationFailed
	if !errors.As(err, &addrErr) || addrErr.Address != failing {
		t.Fatalf("Sweep = %v, want the failed lookup on eth1", err)
	}
	if len(prog.deleted) != 1 || prog.deleted[0] != deleted {
		t.Fatalf("deleted = %v, want %v", prog.deleted, deleted)
	}
	entries, err := inv.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if want := []InventoryEntry{{"eth1", 20, failing}}; len(entries) != 1 || entries[0] != want[0] {
		t.Fatalf("entries = %v, want %v: a missing interface's VIP is forgotten, a failed lookup's kept", entries, want)
	}
}

// sweepProgrammer is a Programmer whose DeleteAddress fails for failing.
type sweepProgrammer struct {
	failing netip.Prefix
	deleted []netip.Prefix
}

func (p *sweepProgrammer) AddAddress(string, netip.Prefix, net.HardwareAddr) error { return nil }
func (p *sweepProgrammer) DeleteAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	if prefix == p.failing {
		return &ErrSpeakerNotRunning{}
	}
	p.deleted = append(p.deleted, prefix)
	return nil
}
func (p *sweepProgrammer) Announce(string, netip.Addr, net.HardwareAddr) error { return nil }

func TestInventory_RecordForgetAndSweep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fhrp")
	path := filepath.Join(dir, VIPInventoryFile)
	inv := NewInventory(path)
	a := netip.MustParsePrefix("192.0.2.1/24")
	b := netip.MustParsePrefix("2001:db8::1/64")
	c := netip.MustParsePrefix("198.51.100.1/24")

	for _, rec := range []struct {
		iface string
		vrid  uint8
		p     netip.Prefix
	}{{"eth0", 1, a}, {"eth0", 1, a}, {"eth1", 2, b}, {"eth2", 3, c}} {
		if err := inv.Record(rec.iface, rec.vrid, rec.p); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	entries, err := inv.Entries()
	if err != nil || len(entries) != 3 {
		t.Fatalf("Entries = %v, %v; want 3 (a duplicate is recorded once)", entries, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, VIPInventoryFile+".tmp*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}

	if err := inv.Forget("eth2", 3, c); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	prog := &sweepProgrammer{failing: b}
	err = inv.Sweep(prog, func(InventoryEntry) bool { return false })
	var invErr *ErrInventory
	var addrErr *ErrAddressOperationFailed
	if !errors.As(err, &invErr) || !errors.As(err, &addrErr) || addrErr.Address != b {
		t.Fatalf("Sweep = %v, want *ErrInventory wrapping the failed delete of %s", err, b)
	}
	entries, err = inv.Entries()
	if err != nil || len(entries) != 1 || entries[0].Prefix != b {
		t.Fatalf("after sweep Entries = %v, %v; want only the failed %s", entries, err, b)
	}
	if len(prog.deleted) != 1 || prog.deleted[0] != a {
		t.Fatalf("deleted %v, want [%s]", prog.deleted, a)
	}
}

func TestInventory_NilAndMissingFileRecordNothing(t *testing.T) {
	var none *Inventory
	if NewInventory("") != nil {
		t.Fatal("an empty path is no inventory")
	}
	if err := none.Record("eth0", 1, netip.MustParsePrefix("192.0.2.1/24")); err != nil {
		t.Fatalf("nil Record: %v", err)
	}
	if err := none.Sweep(&sweepProgrammer{}, func(InventoryEntry) bool { return false }); err != nil {
		t.Fatalf("nil Sweep: %v", err)
	}
	path := filepath.Join(t.TempDir(), VIPInventoryFile)
	if entries, err := NewInventory(path).Entries(); err != nil || len(entries) != 0 {
		t.Fatalf("missing file Entries = %v, %v", entries, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading created the file: %v", err)
	}
}
