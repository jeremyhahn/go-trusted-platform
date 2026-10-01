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

package nat64

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Instance is the rendered translator configuration: everything the driver
// needs to bring one NAT64 instance to the desired state. It is a value so
// it can be compared, logged and golden-tested without a kernel.
type Instance struct {
	// Name is the instance name.
	Name string

	// Pool6 is the RFC 6052 translation prefix.
	Pool6 string

	// Pool4 are the IPv4 ranges, in configuration order.
	Pool4 []Pool4Range

	// Timeouts are the resolved RFC 6146 session lifetimes.
	Timeouts SessionTimeouts
}

// Stats is what the translator reports about itself. Health is derived from
// it, so every field is something the kernel actually told us rather than
// something the service assumed.
type Stats struct {
	// Present reports whether the instance exists in the kernel.
	Present bool

	// Sessions is the number of live translation sessions.
	Sessions uint64

	// Pool4Used is the number of allocated address:port pairs.
	Pool4Used uint64

	// ModuleVersion is the translator's reported version, empty when the
	// driver could not read it.
	ModuleVersion string
}

// Driver programs the kernel translator. Apply brings the instance to the
// described state and is idempotent — it is called on every Start and every
// Reconcile, and converges what it finds instead of tearing down, because
// the datapath is kernel-resident and must survive a control process that
// exits without stopping the service. Remove deletes the instance; Stats
// reports what the kernel holds.
//
// The Service is written against this interface so the whole service is
// exercised without a kernel module, and JoolDriver is the one
// implementation that talks to a real one.
type Driver interface {
	// Apply converges the kernel instance onto inst. It reports whether it
	// created the instance, so a caller rolling back a failed start removes
	// an instance it made and never one it adopted.
	Apply(ctx context.Context, inst Instance) (created bool, err error)

	// Remove deletes the named instance. An instance that is already gone
	// is not an error.
	Remove(ctx context.Context, name string) error

	// Stats reports the named instance's live state.
	Stats(ctx context.Context, name string) (Stats, error)
}

// joolTimeout renders a duration in Jool's HH:MM:SS form. Jool parses
// nothing else, and a Go duration string ("2h4m0s") is silently rejected.
func joolTimeout(d time.Duration) string {
	total := int64(d / time.Second)
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	return strconv.FormatInt(h, 10) + ":" +
		pad2(m) + ":" + pad2(s)
}

// pad2 renders a two-digit field.
func pad2(v int64) string {
	if v < 10 {
		return "0" + strconv.FormatInt(v, 10)
	}
	return strconv.FormatInt(v, 10)
}

// Command is one translator command line: the argv the driver runs, kept as
// data so it is golden-tested and logged rather than assembled inline at
// the exec site.
type Command []string

// String renders the command for logs and golden files.
func (c Command) String() string { return strings.Join(c, " ") }

// pool4Protocols are the L4 protocols a NAT64 pool4 range is registered
// for, as the flag the jool tool takes and the name its display prints.
// Jool keeps one table per protocol; omitting one means that protocol has
// no addresses to translate to and its traffic is dropped.
var pool4Protocols = []struct{ flag, display string }{
	{"--tcp", "TCP"},
	{"--udp", "UDP"},
	{"--icmp", "ICMP"},
}

// pool4Entry is one pool4 registration as the kernel holds it: one address,
// one protocol, one port range. `jool pool4 display` lists a prefix added
// in one command as one row per address, so convergence compares at that
// grain.
type pool4Entry struct {
	proto     string
	addr      netip.Addr
	portStart uint16
	portEnd   uint16
}

// ports renders the entry's port range the way the jool tool takes it.
func (e pool4Entry) ports() string {
	return strconv.FormatUint(uint64(e.portStart), 10) + "-" + strconv.FormatUint(uint64(e.portEnd), 10)
}

// rangePrefixes covers the inclusive IPv4 range [first, last] with the
// fewest CIDR prefixes. The jool tool takes a prefix, not a range: it
// refuses "a-b" outright, so a range from the configuration is registered
// as the prefixes that tile it exactly.
func rangePrefixes(first, last netip.Addr) []netip.Prefix {
	lo := ipv4Uint(first)
	hi := ipv4Uint(last)
	var out []netip.Prefix
	for lo <= hi {
		// The largest block aligned at lo that does not run past hi.
		bits := 32
		for bits > 0 {
			size := uint64(1) << (32 - (bits - 1))
			if lo%size != 0 || lo+size-1 > hi {
				break
			}
			bits--
		}
		out = append(out, netip.PrefixFrom(uint32IPv4(uint32(lo)), bits))
		lo += uint64(1) << (32 - bits)
	}
	return out
}

func ipv4Uint(a netip.Addr) uint64 {
	b := a.As4()
	return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
}

func uint32IPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// pool4Prefixes resolves every configured range to the prefixes that tile
// it. Ranges reaching the driver were validated by the service, so a range
// that does not parse is a programming error reported as such.
func pool4Prefixes(inst Instance) ([]netip.Prefix, []Pool4Range, error) {
	var prefixes []netip.Prefix
	var owners []Pool4Range
	for _, r := range inst.Pool4 {
		p, err := parsePool4(r.Addresses, r.PortStart, r.PortEnd)
		if err != nil {
			return nil, nil, err
		}
		for _, pfx := range rangePrefixes(p.first, p.last) {
			prefixes = append(prefixes, pfx)
			owners = append(owners, r)
		}
	}
	return prefixes, owners, nil
}

// desiredPool4 is the per-address, per-protocol set the instance should
// hold.
func desiredPool4(inst Instance) (map[pool4Entry]struct{}, error) {
	out := make(map[pool4Entry]struct{})
	for _, r := range inst.Pool4 {
		p, err := parsePool4(r.Addresses, r.PortStart, r.PortEnd)
		if err != nil {
			return nil, err
		}
		for a := p.first; ; a = a.Next() {
			for _, proto := range pool4Protocols {
				out[pool4Entry{proto: proto.display, addr: a, portStart: p.portStart, portEnd: p.portEnd}] = struct{}{}
			}
			if a == p.last {
				break
			}
		}
	}
	return out, nil
}

// RenderCreate is the command sequence that brings a missing instance into
// existence: the instance itself, then every pool4 prefix for every
// protocol, then the session lifetimes. Rendering is separated from running
// so the exact command line is a test fixture, not a runtime surprise.
func RenderCreate(inst Instance) ([]Command, error) {
	cmds := []Command{
		{"jool", "instance", "add", inst.Name, "--netfilter", "--pool6", inst.Pool6},
	}
	pool4, err := RenderPool4(inst)
	if err != nil {
		return nil, err
	}
	cmds = append(cmds, pool4...)
	cmds = append(cmds, RenderTimeouts(inst)...)
	return cmds, nil
}

// RenderPool4 is the pool4 registration for every range and protocol, each
// range as the CIDR prefixes that tile it.
func RenderPool4(inst Instance) ([]Command, error) {
	prefixes, owners, err := pool4Prefixes(inst)
	if err != nil {
		return nil, err
	}
	var cmds []Command
	for i, pfx := range prefixes {
		ports := strconv.FormatUint(uint64(owners[i].PortStart), 10) + "-" + strconv.FormatUint(uint64(owners[i].PortEnd), 10)
		for _, proto := range pool4Protocols {
			cmds = append(cmds, Command{
				"jool", "--instance", inst.Name, "pool4", "add", proto.flag, pfx.String(), ports,
			})
		}
	}
	return cmds, nil
}

// RenderTimeouts is the session-lifetime configuration.
func RenderTimeouts(inst Instance) []Command {
	t := inst.Timeouts
	return []Command{
		{"jool", "--instance", inst.Name, "global", "update", "udp-timeout", joolTimeout(t.UDP)},
		{"jool", "--instance", inst.Name, "global", "update", "tcp-est-timeout", joolTimeout(t.TCPEstablished)},
		{"jool", "--instance", inst.Name, "global", "update", "tcp-trans-timeout", joolTimeout(t.TCPTransitory)},
		{"jool", "--instance", inst.Name, "global", "update", "icmp-timeout", joolTimeout(t.ICMP)},
	}
}

// RenderRemove is the command that deletes an instance.
func RenderRemove(name string) Command {
	return Command{"jool", "instance", "remove", name}
}

// pool4EntryCommand renders the add or remove of one per-address entry.
func pool4EntryCommand(name, verb string, e pool4Entry) Command {
	return Command{"jool", "--instance", name, "pool4", verb, "--" + strings.ToLower(e.proto), e.addr.String(), e.ports()}
}

// runner runs one command and returns its combined output. The interface
// exists so the driver's own logic — the reconcile decision, the parsing,
// the error wrapping — is tested without a kernel module or a jool binary.
type runner interface {
	Run(ctx context.Context, cmd Command) ([]byte, error)
}

// execRunner runs commands with os/exec.
type execRunner struct{}

// Run implements runner.
func (execRunner) Run(ctx context.Context, cmd Command) ([]byte, error) {
	if len(cmd) == 0 {
		return nil, ErrEmptyCommand
	}
	// #nosec G204 -- every argv element is rendered by this package from
	// validated configuration (a parsed netip prefix, a parsed address
	// range, an integer port, a duration); none is caller-supplied text.
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	return out, err
}

// JoolDriver programs a Jool NAT64 instance through the jool userspace
// tool. Alpine packages the module and the tool together
// (`jool-modules-lts`, `jool-tools`), which is what makes the kernel
// translator the platform's PLAT (ruling R6).
type JoolDriver struct {
	run runner
}

// NewJoolDriver returns a driver that runs the real jool tool.
func NewJoolDriver() *JoolDriver {
	return &JoolDriver{run: execRunner{}}
}

// newJoolDriverWithRunner is the test seam.
func newJoolDriverWithRunner(r runner) *JoolDriver {
	return &JoolDriver{run: r}
}

// Apply implements Driver. It converges rather than recreating: an
// instance that is already present keeps its sessions; only the pool4
// entries that differ are added or removed, and the timeouts are re-set.
//
// The one exception is pool6. Jool refuses to change a NAT64 instance's
// pool6 ("you can't change a NAT64 instance's pool6 for now"), and every
// session maps a client address through it, so a changed prefix has no
// session left worth keeping: the instance is recreated.
func (d *JoolDriver) Apply(ctx context.Context, inst Instance) (bool, error) {
	present, err := d.instancePresent(ctx, inst.Name)
	if err != nil {
		return false, err
	}
	if present {
		pool6, err := d.pool6(ctx, inst.Name)
		if err != nil {
			return false, err
		}
		if pool6 == inst.Pool6 {
			return false, d.converge(ctx, inst)
		}
		if err := d.Remove(ctx, inst.Name); err != nil {
			return false, err
		}
	}
	return true, d.create(ctx, inst)
}

// create brings up a missing instance. A failure part way leaves no
// half-built instance behind.
func (d *JoolDriver) create(ctx context.Context, inst Instance) error {
	cmds, err := RenderCreate(inst)
	if err != nil {
		return err
	}
	for i, cmd := range cmds {
		if err := d.runCmd(ctx, "apply", cmd); err != nil {
			if i == 0 {
				// The instance itself did not come up: nothing to undo,
				// and the module is what refused.
				return &ErrNAT64ModuleUnavailable{Instance: inst.Name, Err: err}
			}
			if rmErr := d.runCmd(ctx, "remove", RenderRemove(inst.Name)); rmErr != nil {
				return errors.Join(err, rmErr)
			}
			return err
		}
	}
	return nil
}

// converge brings a present instance's pool4 and timeouts onto inst.
// Removals go first. jool merges an added port range into an overlapping
// one already held for the same address, and a removal takes the whole
// overlap with it: adding 62000-63000 beside 61001-65535 and then removing
// 61001-65535 leaves the address with nothing (measured on jool 4.1.14).
// An entry being replaced is therefore briefly absent; an entry that does
// not change is never touched.
func (d *JoolDriver) converge(ctx context.Context, inst Instance) error {
	want, err := desiredPool4(inst)
	if err != nil {
		return err
	}
	have, err := d.pool4(ctx, inst.Name)
	if err != nil {
		return err
	}
	for _, e := range sortedEntries(have) {
		if _, ok := want[e]; ok {
			continue
		}
		if err := d.runCmd(ctx, "apply", pool4EntryCommand(inst.Name, "remove", e)); err != nil {
			return err
		}
	}
	for _, e := range sortedEntries(want) {
		if _, ok := have[e]; ok {
			continue
		}
		if err := d.runCmd(ctx, "apply", pool4EntryCommand(inst.Name, "add", e)); err != nil {
			return err
		}
	}
	for _, cmd := range RenderTimeouts(inst) {
		if err := d.runCmd(ctx, "apply", cmd); err != nil {
			return err
		}
	}
	return nil
}

// sortedEntries orders a pool4 set so the commands a convergence runs are
// deterministic: logs and tests read the same sequence every time.
func sortedEntries(set map[pool4Entry]struct{}) []pool4Entry {
	out := make([]pool4Entry, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b pool4Entry) int {
		if c := strings.Compare(a.proto, b.proto); c != 0 {
			return c
		}
		if c := a.addr.Compare(b.addr); c != 0 {
			return c
		}
		if a.portStart != b.portStart {
			return int(a.portStart) - int(b.portStart)
		}
		return int(a.portEnd) - int(b.portEnd)
	})
	return out
}

// runCmd runs one command, wrapping a failure with the command line and the
// tool's output.
func (d *JoolDriver) runCmd(ctx context.Context, op string, cmd Command) error {
	out, err := d.run.Run(ctx, cmd)
	if err != nil {
		return &OpError{Op: op, Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
	}
	return nil
}

// pool6 reads the instance's translation prefix from `jool global display`.
func (d *JoolDriver) pool6(ctx context.Context, name string) (string, error) {
	cmd := Command{"jool", "--instance", name, "global", "display", "--csv"}
	out, err := d.run.Run(ctx, cmd)
	if err != nil {
		return "", &OpError{Op: "read", Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ",")
		if ok && key == "pool6" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", &OpError{Op: "read", Err: &CommandError{Cmd: cmd, Output: trim(out), Err: ErrPool6Unreadable}}
}

// pool4 reads the instance's pool4 as per-address entries, one protocol
// at a time: `jool pool4 display` without a protocol flag shows the TCP
// table only. The CSV is "Mark,Protocol,Address,Min port,Max port,
// Iterations,Iterations fixed"; a row with a nonzero mark is not this
// service's and is left alone.
func (d *JoolDriver) pool4(ctx context.Context, name string) (map[pool4Entry]struct{}, error) {
	have := make(map[pool4Entry]struct{})
	for _, proto := range pool4Protocols {
		cmd := Command{"jool", "--instance", name, "pool4", "display", proto.flag, "--csv", "--no-headers"}
		out, err := d.run.Run(ctx, cmd)
		if err != nil {
			return nil, &OpError{Op: "read", Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
		}
		for _, line := range strings.Split(string(out), "\n") {
			if e, ok := parsePool4Row(line); ok {
				have[e] = struct{}{}
			}
		}
	}
	return have, nil
}

// parsePool4Row parses one `pool4 display --csv` row, reporting false for
// a header, a blank line, another mark's row, or anything malformed.
func parsePool4Row(line string) (pool4Entry, bool) {
	fields := strings.Split(strings.TrimSpace(line), ",")
	if len(fields) < 5 || strings.TrimSpace(fields[0]) != "0" {
		return pool4Entry{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(fields[2]))
	if err != nil {
		return pool4Entry{}, false
	}
	lo, errLo := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 16)
	hi, errHi := strconv.ParseUint(strings.TrimSpace(fields[4]), 10, 16)
	if errLo != nil || errHi != nil {
		return pool4Entry{}, false
	}
	return pool4Entry{proto: strings.TrimSpace(fields[1]), addr: addr, portStart: uint16(lo), portEnd: uint16(hi)}, true
}

// Remove implements Driver.
func (d *JoolDriver) Remove(ctx context.Context, name string) error {
	present, err := d.instancePresent(ctx, name)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	cmd := RenderRemove(name)
	if out, err := d.run.Run(ctx, cmd); err != nil {
		return &OpError{Op: "remove", Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
	}
	return nil
}

// Stats implements Driver.
func (d *JoolDriver) Stats(ctx context.Context, name string) (Stats, error) {
	present, err := d.instancePresent(ctx, name)
	if err != nil {
		return Stats{}, err
	}
	if !present {
		return Stats{}, nil
	}
	stats := Stats{Present: true}
	cmd := Command{"jool", "--instance", name, "stats", "display", "--csv"}
	out, err := d.run.Run(ctx, cmd)
	if err != nil {
		return Stats{}, &OpError{Op: "stats", Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
	}
	stats.Sessions, stats.Pool4Used = parseStatsCSV(out)
	if version, err := d.version(ctx); err == nil {
		stats.ModuleVersion = version
	}
	return stats, nil
}

// version reads the translator's reported version; a failure is not fatal
// to health, so the caller ignores the error.
func (d *JoolDriver) version(ctx context.Context) (string, error) {
	out, err := d.run.Run(ctx, Command{"jool", "--version"})
	if err != nil {
		return "", err
	}
	return trim(out), nil
}

// instancePresent reports whether the named instance exists.
func (d *JoolDriver) instancePresent(ctx context.Context, name string) (bool, error) {
	cmd := Command{"jool", "instance", "display", "--csv"}
	out, err := d.run.Run(ctx, cmd)
	if err != nil {
		return false, &ErrNAT64ModuleUnavailable{Instance: name, Err: &CommandError{Cmd: cmd, Output: trim(out), Err: err}}
	}
	// "Namespace,Name,Framework": the name is the second column. Matching
	// any column would take a namespace id that happens to equal the name
	// for the instance.
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) >= 2 && strings.TrimSpace(fields[1]) == name {
			return true, nil
		}
	}
	return false, nil
}

// statsKeys maps the Jool stats counter names this service reads onto the
// Stats fields they fill. Map dispatch keeps the parse O(1) per line and
// the counter vocabulary in one place.
var statsKeys = map[string]func(*Stats, uint64){
	"JSTAT_BIB_ENTRIES":     func(s *Stats, v uint64) { s.Pool4Used = v },
	"JSTAT_SESSIONS":        func(s *Stats, v uint64) { s.Sessions = v },
	"JSTAT_SESSION_ENTRIES": func(s *Stats, v uint64) { s.Sessions = v },
}

// parseStatsCSV reads the counters this service reports from `jool stats
// display --csv` output ("KEY,value" per line). Unknown counters are
// ignored: Jool adds them between releases, and an unknown counter is not a
// reason to call the translator unhealthy.
func parseStatsCSV(out []byte) (sessions, pool4Used uint64) {
	var s Stats
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) < 2 {
			continue
		}
		apply, ok := statsKeys[strings.TrimSpace(fields[0])]
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(fields[len(fields)-1]), 10, 64)
		if err != nil {
			continue
		}
		apply(&s, v)
	}
	return s.Sessions, s.Pool4Used
}

// trim returns the command output as a single-line string for errors.
func trim(out []byte) string {
	return strings.TrimSpace(string(out))
}
