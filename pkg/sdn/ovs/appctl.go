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

package ovs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultAppCtlRunDir is the default OVS runtime directory containing the
// ovs-vswitchd pid file and unixctl control socket.
const DefaultAppCtlRunDir = "/var/run/openvswitch"

// appctlPidFile is the pid file ovs-vswitchd writes into its run directory.
const appctlPidFile = "ovs-vswitchd.pid"

// AppCtlRunner is the interface for issuing ovs-appctl (unixctl) commands
// against a running ovs-vswitchd. *Client implements it; the daemon perf
// service consumes it so unit tests can inject fakes.
type AppCtlRunner interface {
	// AppCtl issues a raw unixctl command and returns the reply text.
	AppCtl(ctx context.Context, method string, args ...string) (string, error)

	// DumpDatapathFlows returns dpctl/dump-flows output. filter is passed
	// through verbatim when non-empty (e.g. "type=offloaded").
	DumpDatapathFlows(ctx context.Context, filter string) (string, error)

	// DumpConntrack returns dpctl/dump-conntrack output. A negative zone
	// dumps every zone; zone >= 0 restricts the dump to that zone.
	DumpConntrack(ctx context.Context, zone int) (string, error)

	// CoverageShow returns coverage/show counters.
	CoverageShow(ctx context.Context) (string, error)

	// PMDStats returns dpif-netdev/pmd-stats-show output. On the kernel
	// datapath ovs-vswitchd rejects the command; the error text is passed
	// through as an ErrAppCtlCommandFailed.
	PMDStats(ctx context.Context) (string, error)

	// DatapathStats returns dpctl/show -s output (per-datapath hit /
	// missed / lost lookup counters plus per-port statistics).
	DatapathStats(ctx context.Context) (string, error)
}

// Compile-time check: *Client provides the appctl surface.
var _ AppCtlRunner = (*Client)(nil)

// ErrAppCtlPidFileUnavailable is returned when the ovs-vswitchd pid file
// cannot be read from the configured run directory.
type ErrAppCtlPidFileUnavailable struct {
	// Path is the pid file path that could not be read.
	Path string

	// Cause is the underlying filesystem error.
	Cause error
}

// Error implements the error interface.
func (e *ErrAppCtlPidFileUnavailable) Error() string {
	return "ovs-appctl: pid file unavailable at " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrAppCtlPidFileUnavailable) Unwrap() error { return e.Cause }

// ErrAppCtlInvalidPid is returned when the pid file contents are not a
// positive integer.
type ErrAppCtlInvalidPid struct {
	// Path is the pid file path.
	Path string

	// Contents is the raw (trimmed) pid file contents.
	Contents string
}

// Error implements the error interface.
func (e *ErrAppCtlInvalidPid) Error() string {
	return "ovs-appctl: invalid pid " + strconv.Quote(e.Contents) + " in " + e.Path
}

// ErrAppCtlSocketUnavailable is returned when the composed unixctl control
// socket cannot be dialed.
type ErrAppCtlSocketUnavailable struct {
	// Path is the control socket path.
	Path string

	// Cause is the underlying dial error.
	Cause error
}

// Error implements the error interface.
func (e *ErrAppCtlSocketUnavailable) Error() string {
	return "ovs-appctl: control socket unavailable at " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrAppCtlSocketUnavailable) Unwrap() error { return e.Cause }

// ErrAppCtlCommandFailed is returned when ovs-vswitchd rejects a unixctl
// command. Reply carries the daemon's error text verbatim.
type ErrAppCtlCommandFailed struct {
	// Method is the unixctl command that failed.
	Method string

	// Reply is the error text returned by ovs-vswitchd.
	Reply string
}

// Error implements the error interface.
func (e *ErrAppCtlCommandFailed) Error() string {
	return "ovs-appctl: " + e.Method + " failed: " + e.Reply
}

// ErrAppCtlProtocol is returned when the unixctl reply cannot be decoded
// or carries neither a result nor an error.
type ErrAppCtlProtocol struct {
	// Method is the unixctl command whose reply was malformed.
	Method string

	// Cause is the underlying decode error, when any.
	Cause error
}

// Error implements the error interface.
func (e *ErrAppCtlProtocol) Error() string {
	msg := "ovs-appctl: malformed unixctl reply for " + e.Method
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause.
func (e *ErrAppCtlProtocol) Unwrap() error { return e.Cause }

// ErrDatapathStatsUnparseable is returned when dpctl/show -s output does
// not contain a recognizable lookups line.
type ErrDatapathStatsUnparseable struct {
	// Output is the raw dpctl/show -s output.
	Output string
}

// Error implements the error interface.
func (e *ErrDatapathStatsUnparseable) Error() string {
	return "ovs-appctl: no datapath lookups counters found in dpctl/show -s output"
}

// WithAppCtlRunDir sets the OVS runtime directory used to discover the
// ovs-vswitchd unixctl control socket (default /var/run/openvswitch).
func WithAppCtlRunDir(dir string) ClientOption {
	return func(c *Client) {
		c.appctlRunDir = dir
	}
}

// unixctlReply is the unixctl JSON-RPC reply shape. Unlike OVSDB replies
// (RPCError objects), unixctl carries plain strings for both result and
// error, so it needs its own decode type; requests reuse JSONRPCRequest.
type unixctlReply struct {
	Result *string `json:"result"`
	Error  *string `json:"error"`
	ID     uint64  `json:"id"`
}

// appctlSocketPath discovers the unixctl control socket by reading the
// ovs-vswitchd pid file and composing <rundir>/ovs-vswitchd.<pid>.ctl,
// exactly like the ovs-appctl tool does.
func (c *Client) appctlSocketPath() (string, error) {
	runDir := c.appctlRunDir
	if runDir == "" {
		runDir = DefaultAppCtlRunDir
	}

	pidPath := filepath.Join(runDir, appctlPidFile)
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return "", &ErrAppCtlPidFileUnavailable{Path: pidPath, Cause: err}
	}

	contents := strings.TrimSpace(string(raw))
	pid, err := strconv.Atoi(contents)
	if err != nil || pid <= 0 {
		return "", &ErrAppCtlInvalidPid{Path: pidPath, Contents: contents}
	}

	return filepath.Join(runDir, fmt.Sprintf("ovs-vswitchd.%d.ctl", pid)), nil
}

// AppCtl issues a unixctl command against the running ovs-vswitchd and
// returns the reply text. Each call uses a dedicated connection, mirroring
// ovs-appctl's one-shot semantics; the OVSDB dispatcher connection is not
// involved.
func (c *Client) AppCtl(ctx context.Context, method string, args ...string) (string, error) {
	socketPath, err := c.appctlSocketPath()
	if err != nil {
		return "", err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return "", &ErrAppCtlSocketUnavailable{Path: socketPath, Cause: err}
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", &ErrAppCtlProtocol{Method: method, Cause: err}
		}
	}

	params := make([]interface{}, 0, len(args))
	for _, arg := range args {
		params = append(params, arg)
	}

	req := NewJSONRPCRequest(method, params)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return "", &ErrAppCtlProtocol{Method: method, Cause: err}
	}

	var reply unixctlReply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return "", &ErrAppCtlProtocol{Method: method, Cause: err}
	}

	if reply.Error != nil {
		return "", &ErrAppCtlCommandFailed{Method: method, Reply: *reply.Error}
	}
	if reply.Result == nil {
		return "", &ErrAppCtlProtocol{Method: method}
	}
	return *reply.Result, nil
}

// DumpDatapathFlows returns the datapath flow table (dpctl/dump-flows).
// filter is passed through verbatim when non-empty, e.g. "type=offloaded"
// to restrict the dump to hardware-offloaded flows.
func (c *Client) DumpDatapathFlows(ctx context.Context, filter string) (string, error) {
	if filter == "" {
		return c.AppCtl(ctx, "dpctl/dump-flows")
	}
	return c.AppCtl(ctx, "dpctl/dump-flows", filter)
}

// DumpConntrack returns the connection tracking table
// (dpctl/dump-conntrack). A negative zone dumps every zone; zone >= 0
// restricts the dump to that conntrack zone.
func (c *Client) DumpConntrack(ctx context.Context, zone int) (string, error) {
	if zone < 0 {
		return c.AppCtl(ctx, "dpctl/dump-conntrack")
	}
	return c.AppCtl(ctx, "dpctl/dump-conntrack", "zone="+strconv.Itoa(zone))
}

// CoverageShow returns ovs-vswitchd's coverage/show event counters.
func (c *Client) CoverageShow(ctx context.Context) (string, error) {
	return c.AppCtl(ctx, "coverage/show")
}

// PMDStats returns dpif-netdev/pmd-stats-show output for the userspace
// (DPDK) datapath. On the kernel datapath ovs-vswitchd rejects the command
// and the daemon's error text is passed through as ErrAppCtlCommandFailed.
func (c *Client) PMDStats(ctx context.Context) (string, error) {
	return c.AppCtl(ctx, "dpif-netdev/pmd-stats-show")
}

// DatapathStats returns dpctl/show -s output: per-datapath hit / missed /
// lost lookup counters plus per-port statistics.
func (c *Client) DatapathStats(ctx context.Context) (string, error) {
	return c.AppCtl(ctx, "dpctl/show", "-s")
}

// DatapathCounters carries the datapath lookup counters parsed from
// dpctl/show -s output.
type DatapathCounters struct {
	// Hits is the number of packets matched in the datapath flow cache.
	Hits uint64

	// Missed is the number of packets upcalled to ovs-vswitchd.
	Missed uint64

	// Lost is the number of upcalls dropped without processing.
	Lost uint64
}

// ParseDatapathStats extracts the hit / missed / lost lookup counters from
// dpctl/show -s output. The expected line format (OVS 3.x) is:
//
//	lookups: hit:1319107 missed:2874 lost:0
//
// When multiple datapaths are present the counters are summed.
func ParseDatapathStats(output string) (DatapathCounters, error) {
	var counters DatapathCounters
	found := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "lookups:") {
			continue
		}
		for _, field := range strings.Fields(strings.TrimPrefix(trimmed, "lookups:")) {
			key, value, ok := strings.Cut(field, ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "hit":
				counters.Hits += n
				found = true
			case "missed":
				counters.Missed += n
				found = true
			case "lost":
				counters.Lost += n
				found = true
			}
		}
	}

	if !found {
		return DatapathCounters{}, &ErrDatapathStatsUnparseable{Output: output}
	}
	return counters, nil
}

// CountOffloadedFlows counts flow entries in dpctl/dump-flows output. Each
// non-empty line is one datapath flow; callers pass the output of a
// type=offloaded dump to count hardware-offloaded flows.
func CountOffloadedFlows(dump string) int {
	count := 0
	for _, line := range strings.Split(dump, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// ConntrackSummary summarizes a dpctl/dump-conntrack dump.
type ConntrackSummary struct {
	// Total is the total number of conntrack entries.
	Total int

	// PerZone maps conntrack zone ID to its entry count. Entries without
	// an explicit zone= key are counted in zone 0.
	PerZone map[int]int
}

// ParseConntrackSummary counts conntrack entries and groups them per zone.
// Each non-empty line of dpctl/dump-conntrack output is one entry; the
// zone is parsed from the "zone=N" field when present (OVS omits it for
// the default zone 0).
func ParseConntrackSummary(dump string) ConntrackSummary {
	summary := ConntrackSummary{PerZone: make(map[int]int)}
	for _, line := range strings.Split(dump, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		summary.Total++
		summary.PerZone[conntrackZone(trimmed)]++
	}
	return summary
}

// conntrackZone extracts the zone ID from one conntrack entry line,
// defaulting to zone 0 when no zone= field is present.
func conntrackZone(line string) int {
	for _, field := range strings.Split(line, ",") {
		value, ok := strings.CutPrefix(strings.TrimSpace(field), "zone=")
		if !ok {
			continue
		}
		// The zone value may be followed by further comma-free content;
		// it is always a bare decimal in dump-conntrack output.
		if zone, err := strconv.Atoi(value); err == nil {
			return zone
		}
	}
	return 0
}
