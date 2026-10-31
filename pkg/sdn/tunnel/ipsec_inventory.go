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
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	vnl "github.com/vishvananda/netlink"
)

// ipsecInventoryMode keeps the record to the gateway: it names which ESP
// state the next start may remove.
const ipsecInventoryMode = 0o600

// ipsecPairRecord names one ESP pair by its anchor, the outbound SA: the
// request id and the anchor's source and destination.
type ipsecPairRecord struct {
	Reqid int    `json:"reqid"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
}

// ipsecSARecord names one SA the platform installed by its kernel identity
// (destination and SPI) and its source.
type ipsecSARecord struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	SPI int    `json:"spi"`
}

// ipsecPolicyRecord names one protection policy the platform installed by its
// selector (source, destination, protocol and direction) and its template's
// endpoints; the template's request id is the pair's.
type ipsecPolicyRecord struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Proto   int    `json:"proto"`
	Dir     int    `json:"dir"`
	TmplSrc string `json:"tmpl_src"`
	TmplDst string `json:"tmpl_dst"`
}

// ipsecInventoryEntry is one pair as the inventory file holds it: the pair's
// record, every SA and policy installed under it and the name of every
// carrier link its tunnels ran over.
//
// The SAs are recorded one by one because the pair's request id and
// endpoints do not say who installed an SA: an IKE daemon may add a transport
// AES-GCM SA under the same request id between the same hosts, so the sweep
// removes only an SA whose identity the platform recorded. An inbound SPI a
// later configuration replaced stays recorded until it is swept.
//
// The carriers are recorded for the same reason: a link's endpoints and
// protocol do not say who installed it, since another installer's GRE or IPIP
// link between the same hosts matches a stale policy just as the platform's
// does, so the sweep removes only a link whose name the platform recorded.
// A carrier stays recorded until it is removed, even when a tunnel of another
// name reuses the pair, so a replaced carrier is still retired before its
// policies go.
//
// The policies are recorded for the same reason again: a policy whose
// template names the pair's request id and endpoints may still be another
// installer's, an IPIP policy beside the platform's GRE one, so the sweep
// removes only a policy whose selector and template the platform recorded.
type ipsecInventoryEntry struct {
	ipsecPairRecord
	Carriers []string            `json:"carriers"`
	SAs      []ipsecSARecord     `json:"sas"`
	Policies []ipsecPolicyRecord `json:"policies"`
}

// recordOf is the record of the pair whose anchor is s.
func recordOf(s *vnl.XfrmState) ipsecPairRecord {
	return ipsecPairRecord{Reqid: s.Reqid, Src: s.Src.String(), Dst: s.Dst.String()}
}

// saRecordOf is the record of the SA s.
func saRecordOf(s *vnl.XfrmState) ipsecSARecord {
	return ipsecSARecord{Src: s.Src.String(), Dst: s.Dst.String(), SPI: s.Spi}
}

// policyRecordOf is the record of the policy p, which carries one template.
func policyRecordOf(p *vnl.XfrmPolicy) ipsecPolicyRecord {
	t := p.Tmpls[0]
	return ipsecPolicyRecord{
		Src: p.Src.String(), Dst: p.Dst.String(), Proto: int(p.Proto), Dir: int(p.Dir),
		TmplSrc: t.Src.String(), TmplDst: t.Dst.String(),
	}
}

// ownsSA reports whether the entry records installing s.
func (e *ipsecInventoryEntry) ownsSA(s *vnl.XfrmState) bool {
	return slices.Contains(e.SAs, saRecordOf(s))
}

// ipsecInventory is the durable record of the ESP pairs this platform
// installed. The kernel carries no marker that tells the platform's SAs from
// an identical pair another installer added (same shape, and an SPI equal to
// the request id), so ownership is what this record says: a pair, its SAs,
// policies and carrier are written here before the SAs are added, the pair is
// dropped once its anchor is removed, and the sweep and the move retirement
// touch only a recorded pair, SA, policy or carrier. A manager without an inventory
// proves no pair its own and so removes nothing it did not install in this
// process.
type ipsecInventory struct {
	path string
}

// load reads the recorded pairs, each keyed by its record. A record never
// written holds none.
func (inv *ipsecInventory) load() (map[ipsecPairRecord]*ipsecInventoryEntry, error) {
	recorded := make(map[ipsecPairRecord]*ipsecInventoryEntry)
	if inv == nil {
		return recorded, nil
	}
	data, err := os.ReadFile(inv.path)
	if errors.Is(err, fs.ErrNotExist) {
		return recorded, nil
	}
	if err != nil {
		return nil, &ErrIPsecInventory{Path: inv.path, Op: "read", Cause: err}
	}
	var entries []ipsecInventoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, &ErrIPsecInventory{Path: inv.path, Op: "decode", Cause: err}
	}
	for i := range entries {
		recorded[entries[i].ipsecPairRecord] = &entries[i]
	}
	return recorded, nil
}

// add records the pair whose anchor is out, its SAs out and in, the carrier
// link it protects and the policies that protect it, beside whatever the
// pair already records. It runs before the pair's SAs, policies and carrier
// are added, so a manager killed in between leaves a record of state that
// may exist rather than state no record proves.
func (inv *ipsecInventory) add(out, in *vnl.XfrmState, carrier string, policies ...*vnl.XfrmPolicy) error {
	if inv == nil {
		return nil
	}
	recorded, err := inv.load()
	if err != nil {
		return err
	}
	rec := recordOf(out)
	entry, ok := recorded[rec]
	if !ok {
		entry = &ipsecInventoryEntry{ipsecPairRecord: rec}
		recorded[rec] = entry
	}
	changed := !ok
	if !slices.Contains(entry.Carriers, carrier) {
		entry.Carriers = append(entry.Carriers, carrier)
		changed = true
	}
	for _, s := range []*vnl.XfrmState{out, in} {
		if !entry.ownsSA(s) {
			entry.SAs = append(entry.SAs, saRecordOf(s))
			changed = true
		}
	}
	for _, p := range policies {
		if rec := policyRecordOf(p); !slices.Contains(entry.Policies, rec) {
			entry.Policies = append(entry.Policies, rec)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return inv.store(recorded)
}

// forget drops from the pair whose anchor is anchor the SAs, policies and
// carriers the sweep removed, keeping the pair itself.
func (inv *ipsecInventory) forget(anchor *vnl.XfrmState, sas []ipsecSARecord, policies []ipsecPolicyRecord, carriers []string) error {
	if inv == nil || (len(sas) == 0 && len(policies) == 0 && len(carriers) == 0) {
		return nil
	}
	recorded, err := inv.load()
	if err != nil {
		return err
	}
	entry, ok := recorded[recordOf(anchor)]
	if !ok {
		return nil
	}
	entry.SAs = slices.DeleteFunc(entry.SAs, func(r ipsecSARecord) bool { return slices.Contains(sas, r) })
	entry.Policies = slices.DeleteFunc(entry.Policies, func(r ipsecPolicyRecord) bool { return slices.Contains(policies, r) })
	entry.Carriers = slices.DeleteFunc(entry.Carriers, func(c string) bool { return slices.Contains(carriers, c) })
	return inv.store(recorded)
}

// remove drops the record of the pair whose anchor is s, once that anchor is
// gone from the kernel.
func (inv *ipsecInventory) remove(s *vnl.XfrmState) error {
	if inv == nil {
		return nil
	}
	recorded, err := inv.load()
	if err != nil {
		return err
	}
	rec := recordOf(s)
	if _, ok := recorded[rec]; !ok {
		return nil
	}
	delete(recorded, rec)
	return inv.store(recorded)
}

// store replaces the record in one rename, so a reader never sees half of it.
// A record with no pair left removes the file: gatewayd reads the file's
// existence as recorded tunnel state a tunnel-less start must sweep.
func (inv *ipsecInventory) store(recorded map[ipsecPairRecord]*ipsecInventoryEntry) error {
	if len(recorded) == 0 {
		if err := os.Remove(inv.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return &ErrIPsecInventory{Path: inv.path, Op: "remove", Cause: err}
		}
		return nil
	}
	entries := make([]ipsecInventoryEntry, 0, len(recorded))
	for _, entry := range recorded {
		slices.Sort(entry.Carriers)
		slices.SortFunc(entry.SAs, compareSARecords)
		slices.SortFunc(entry.Policies, comparePolicyRecords)
		entries = append(entries, *entry)
	}
	slices.SortFunc(entries, compareEntries)
	data, err := json.Marshal(entries)
	if err != nil {
		return &ErrIPsecInventory{Path: inv.path, Op: "encode", Cause: err}
	}
	if err := os.MkdirAll(filepath.Dir(inv.path), 0o700); err != nil {
		return &ErrIPsecInventory{Path: inv.path, Op: "create directory", Cause: err}
	}
	tmp := inv.path + ".tmp"
	if err := writeFileSynced(tmp, data, ipsecInventoryMode); err != nil {
		return &ErrIPsecInventory{Path: inv.path, Op: "write", Cause: err}
	}
	if err := os.Rename(tmp, inv.path); err != nil {
		return &ErrIPsecInventory{Path: inv.path, Op: "replace", Cause: err}
	}
	return nil
}

// writeFileSynced writes data to path at exactly mode and flushes it to disk
// before the caller renames it over the record. A stale file at path keeps
// no wider mode it had (os.WriteFile sets the mode only on create), and a
// crash after the rename cannot publish an empty record.
func writeFileSynced(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := fillFile(f, data, mode); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// fillFile sets f's mode, writes data and syncs it.
func fillFile(f *os.File, data []byte, mode os.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// compareEntries orders entries so the file is stable across writes.
func compareEntries(a, b ipsecInventoryEntry) int {
	return cmp.Or(cmp.Compare(a.Reqid, b.Reqid), cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst))
}

// compareSARecords orders a pair's SAs so the file is stable across writes.
func compareSARecords(a, b ipsecSARecord) int {
	return cmp.Or(cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.SPI, b.SPI), cmp.Compare(a.Src, b.Src))
}

// comparePolicyRecords orders a pair's policies so the file is stable across
// writes.
func comparePolicyRecords(a, b ipsecPolicyRecord) int {
	return cmp.Or(cmp.Compare(a.Dir, b.Dir), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Src, b.Src),
		cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.TmplSrc, b.TmplSrc), cmp.Compare(a.TmplDst, b.TmplDst))
}
