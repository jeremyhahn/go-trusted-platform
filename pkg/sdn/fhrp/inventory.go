package fhrp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"

	vnl "github.com/vishvananda/netlink"
)

// VIPInventoryFile is the inventory's file name in the fhrp state
// directory under gatewayd's data directory.
const VIPInventoryFile = "vips.json"

// InventoryEntry is one virtual address a speaker installed or adopted.
type InventoryEntry struct {
	Interface string       `json:"interface"`
	VRID      uint8        `json:"vrid"`
	Prefix    netip.Prefix `json:"prefix"`
}

// ErrInventory reports a VIP inventory that could not be read, written or
// swept.
type ErrInventory struct {
	Path  string
	Op    string
	Cause error
}

// Error implements the error interface.
func (e *ErrInventory) Error() string {
	return fmt.Sprintf("fhrp: VIP inventory %s %q: %v", e.Op, e.Path, e.Cause)
}

// Unwrap exposes the cause.
func (e *ErrInventory) Unwrap() error { return e.Cause }

// Inventory records, in one file, every VIP the speaker added or adopted,
// so a gateway restarted with a group removed (or FHRP disabled) can
// delete the addresses a crashed predecessor left on the interface. The
// netlink library cannot tag an address with its owner, so this file is
// the only proof an address is the speaker's. A priority-255 owner's own
// address is never recorded. A nil *Inventory records nothing.
type Inventory struct {
	path string
	mu   sync.Mutex
}

// NewInventory returns the inventory kept at path; an empty path is nil.
func NewInventory(path string) *Inventory {
	if path == "" {
		return nil
	}
	return &Inventory{path: path}
}

// Entries returns the recorded addresses; a missing file records none.
func (inv *Inventory) Entries() ([]InventoryEntry, error) {
	if inv == nil {
		return nil, nil
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.load()
}

// Record adds an entry, rewriting the file when it is new.
func (inv *Inventory) Record(iface string, vrid uint8, p netip.Prefix) error {
	if inv == nil {
		return nil
	}
	e := InventoryEntry{Interface: iface, VRID: vrid, Prefix: p}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	entries, err := inv.load()
	if err != nil {
		return err
	}
	if slices.Contains(entries, e) {
		return nil
	}
	return inv.store(append(entries, e))
}

// Forget removes an entry, rewriting the file when it was recorded.
func (inv *Inventory) Forget(iface string, vrid uint8, p netip.Prefix) error {
	if inv == nil {
		return nil
	}
	e := InventoryEntry{Interface: iface, VRID: vrid, Prefix: p}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	entries, err := inv.load()
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(x InventoryEntry) bool { return x == e })
	if len(kept) == len(entries) {
		return nil
	}
	return inv.store(kept)
}

// Sweep deletes, through prog, every recorded entry keep rejects (a group
// no longer configured, or an address its group no longer configures), and
// rewrites the file with what is left.
// A delete that fails stays recorded and fails the sweep, unless it failed
// because the interface no longer exists: that entry is forgotten.
func (inv *Inventory) Sweep(prog Programmer, keep func(InventoryEntry) bool) error {
	if inv == nil {
		return nil
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	entries, err := inv.load()
	if err != nil {
		return err
	}
	var first error
	kept := make([]InventoryEntry, 0, len(entries))
	for _, e := range entries {
		if keep(e) {
			kept = append(kept, e)
			continue
		}
		fam := FamilyIPv4
		if e.Prefix.Addr().Is6() {
			fam = FamilyIPv6
		}
		if err := prog.DeleteAddress(e.Interface, e.Prefix, VirtualMAC(fam, e.VRID)); err != nil {
			if linkGone(err) {
				// The interface is gone, and its addresses with it.
				continue
			}
			kept = append(kept, e)
			if first == nil {
				first = &ErrAddressOperationFailed{VRID: e.VRID, Interface: e.Interface, Operation: "delete", Address: e.Prefix, Cause: err}
			}
		}
	}
	if len(kept) != len(entries) {
		if err := inv.store(kept); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return &ErrInventory{Path: inv.path, Op: "sweep", Cause: first}
	}
	return nil
}

// linkGone reports whether a delete failed because the link lookup found no
// interface of that name (netlink's typed LinkNotFoundError). Any other
// lookup failure is not proof the address went.
func linkGone(err error) bool {
	var nf vnl.LinkNotFoundError
	return errors.As(err, &nf)
}

func (inv *Inventory) load() ([]InventoryEntry, error) {
	data, err := os.ReadFile(inv.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &ErrInventory{Path: inv.path, Op: "read", Cause: err}
	}
	var entries []InventoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, &ErrInventory{Path: inv.path, Op: "parse", Cause: err}
	}
	return entries, nil
}

// store writes entries to a temporary file beside the inventory and renames
// it over the inventory, so a crash leaves the old file or the new one.
func (inv *Inventory) store(entries []InventoryEntry) error {
	if entries == nil {
		entries = []InventoryEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return &ErrInventory{Path: inv.path, Op: "encode", Cause: err}
	}
	// The supervisor makes the directory for the datapath child; an
	// unsupervised gatewayd makes it here.
	if err := os.MkdirAll(filepath.Dir(inv.path), 0o700); err != nil {
		return &ErrInventory{Path: inv.path, Op: "write", Cause: err}
	}
	tmp, err := os.CreateTemp(filepath.Dir(inv.path), filepath.Base(inv.path)+".tmp*")
	if err != nil {
		return &ErrInventory{Path: inv.path, Op: "write", Cause: err}
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, inv.path)
	}
	if werr != nil {
		_ = os.Remove(name)
		return &ErrInventory{Path: inv.path, Op: "write", Cause: werr}
	}
	return nil
}
