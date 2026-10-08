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

package modes

import (
	"cmp"
	"maps"
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// flowTable is the set of flows the overlay has installed, counted by
// identity: table, priority and match, which is what a switch keys a flow
// on. Several overlay objects can need the same flow — every host behind
// one VTEP needs that VTEP's L3VNI decap authorisation — so a flow is
// installed with its first holder and deleted with its last.
//
// Holders of one identity need not agree on what the flow does. The table
// keeps every version a holder asked for and installs the newest; when the
// last holder of the installed version lets go, the newest version still
// held goes back on the switch, so no holder is left relying on a flow
// that is gone or does something else.
//
// It is not safe for concurrent use; the overlay handler's lock guards it.
type flowTable struct {
	refs map[string]*flowRef
}

// flowRef is every version of one flow identity, oldest first; the last
// is the one installed.
type flowRef struct {
	versions []flowVersion
}

// flowVersion is one set of instructions for a flow and how many overlay
// objects hold it.
type flowVersion struct {
	mod          *openflow.FlowMod
	instructions string
	count        int
}

// flowChange is one identity's part in a plan: the version installed
// before it and the versions it leaves.
type flowChange struct {
	key      string
	before   *flowVersion
	versions []flowVersion
}

// flowPlan is the flow mods that carry a plan out and the mods that put
// back every flow they touch, for a switch that refuses some or all of
// them. Commit records the plan once its mods are on the switch.
type flowPlan struct {
	table   *flowTable
	changes []*flowChange
	mods    []*openflow.FlowMod
	restore []*openflow.FlowMod
}

func newFlowTable() *flowTable {
	return &flowTable{refs: make(map[string]*flowRef)}
}

// plan works out the flow mods that move the switch from the installed
// flows to those left after releasing one set and acquiring another — an
// object's update releases its old flows and acquires its new ones. A
// flow whose installed version changes is replaced in place: the add
// replaces it. New and changed flows come before deletions, so traffic
// moving from one flow to another is never left with neither.
func (t *flowTable) plan(release, acquire []*openflow.FlowMod) (*flowPlan, error) {
	p := &flowPlan{table: t}
	changes := make(map[string]*flowChange)
	changeFor := func(f *openflow.FlowMod) (*flowChange, string, error) {
		key, err := flowKey(f)
		if err != nil {
			return nil, "", err
		}
		instructions, err := instructionBytes(f)
		if err != nil {
			return nil, "", err
		}
		if c, ok := changes[key]; ok {
			return c, string(instructions), nil
		}
		c := &flowChange{key: key}
		if ref, ok := t.refs[key]; ok {
			c.before = newest(ref.versions)
			c.versions = slices.Clone(ref.versions)
		}
		changes[key] = c
		p.changes = append(p.changes, c)
		return c, string(instructions), nil
	}

	for _, f := range release {
		c, instructions, err := changeFor(f)
		if err != nil {
			return nil, err
		}
		i := c.find(instructions)
		if i < 0 || c.versions[i].count == 0 {
			return nil, &ErrFlowOperationFailed{Table: f.TableID, Operation: "release", Cause: ErrFlowNotTracked}
		}
		c.versions[i].count--
	}
	for _, f := range acquire {
		c, instructions, err := changeFor(f)
		if err != nil {
			return nil, err
		}
		if i := c.find(instructions); i >= 0 {
			c.versions[i].count++
			continue
		}
		c.versions = append(c.versions, flowVersion{mod: f, instructions: instructions, count: 1})
	}

	var adds, deletes []*openflow.FlowMod
	for _, c := range p.changes {
		c.versions = slices.DeleteFunc(c.versions, func(v flowVersion) bool { return v.count == 0 })
		switch after := newest(c.versions); {
		case after == nil && c.before != nil:
			deletes = append(deletes, strictDelete(c.before.mod))
			p.restore = append(p.restore, c.before.mod)
		case after != nil && c.before == nil:
			adds = append(adds, after.mod)
			p.restore = append(p.restore, strictDelete(after.mod))
		case after != nil && after.instructions != c.before.instructions:
			adds = append(adds, after.mod)
			p.restore = append(p.restore, c.before.mod)
		}
	}
	p.mods = append(adds, deletes...)
	return p, nil
}

// commit records the plan in the table once its mods are on the switch.
func (p *flowPlan) commit() {
	for _, c := range p.changes {
		if len(c.versions) == 0 {
			delete(p.table.refs, c.key)
			continue
		}
		p.table.refs[c.key] = &flowRef{versions: c.versions}
	}
}

// find is the index of the version with these instructions, or -1.
func (c *flowChange) find(instructions string) int {
	return slices.IndexFunc(c.versions, func(v flowVersion) bool { return v.instructions == instructions })
}

// newest is the version a switch holds for these versions: the last, or
// nil when there are none.
func newest(versions []flowVersion) *flowVersion {
	if len(versions) == 0 {
		return nil
	}
	return &versions[len(versions)-1]
}

// reset forgets every flow, once a cookie-scoped delete has removed them.
func (t *flowTable) reset() {
	clear(t.refs)
}

// installed is the version of every flow the switch should hold, in the
// order failClosed puts them, the same on every call.
func (t *flowTable) installed() []*openflow.FlowMod {
	mods := make([]*openflow.FlowMod, 0, len(t.refs))
	for _, key := range slices.Sorted(maps.Keys(t.refs)) {
		mods = append(mods, newest(t.refs[key].versions).mod)
	}
	return failClosed(mods)
}

// failClosed orders flow adds for a switch that applies them one at a time,
// as OVS applies a batch, so that no part of them passes a frame the whole
// set would drop. The pipeline's last table goes first, so a goto only
// reaches a table that is already complete and table 0's goto, which lets
// frames in at all, goes last; within a table the highest priority goes
// first, so a drop is in place before the broader flow it outranks — the
// table-10 drop of unauthorised tunnelled frames before the table's miss.
// The sort is stable and sorts mods in place.
func failClosed(mods []*openflow.FlowMod) []*openflow.FlowMod {
	slices.SortStableFunc(mods, func(a, b *openflow.FlowMod) int {
		if a.TableID != b.TableID {
			return cmp.Compare(b.TableID, a.TableID)
		}
		return cmp.Compare(b.Priority, a.Priority)
	})
	return mods
}

// flowKey is a flow's identity on the switch: table, priority and match.
func flowKey(f *openflow.FlowMod) (string, error) {
	match, err := f.Match.MarshalBinary()
	if err != nil {
		return "", &ErrFlowOperationFailed{Table: f.TableID, Operation: "key", Cause: err}
	}
	key := make([]byte, 0, 3+len(match))
	key = append(key, f.TableID, byte(f.Priority>>8), byte(f.Priority))
	return string(append(key, match...)), nil
}

// instructionBytes is a flow's instructions on the wire.
func instructionBytes(f *openflow.FlowMod) ([]byte, error) {
	var out []byte
	for _, instruction := range f.Instructions {
		data, err := instruction.MarshalBinary()
		if err != nil {
			return nil, &ErrFlowOperationFailed{Table: f.TableID, Operation: "encode", Cause: err}
		}
		out = append(out, data...)
	}
	return out, nil
}

// strictDelete removes exactly f: same table, priority, match and cookie.
func strictDelete(f *openflow.FlowMod) *openflow.FlowMod {
	d := openflow.NewFlowMod(0)
	d.Command = openflow.OFPFCDeleteStrict
	d.Cookie = f.Cookie
	d.CookieMask = ^uint64(0)
	d.TableID = f.TableID
	d.Priority = f.Priority
	d.Match = f.Match
	return d
}
