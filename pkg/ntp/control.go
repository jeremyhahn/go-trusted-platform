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

package ntp

import (
	"context"
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CommandRunner executes a system command and returns its combined output.
// Every host interaction in this package goes through it, which is what keeps
// unit tests from touching the real clock, RTC, or chronyd.
type CommandRunner interface {
	// Run executes name with args and returns the combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// execRunner is the production CommandRunner backed by os/exec.
type execRunner struct{}

// Run executes the command and returns its combined output.
func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Tracking is chronyd's raw tracking report, one line of `chronyc -c
// tracking`.
type Tracking struct {
	// ReferenceID is the hex reference identifier.
	ReferenceID string

	// ReferenceName is the reference's name or address.
	ReferenceName string

	// Stratum is the node's distance from a reference clock.
	Stratum uint32

	// RefTime is the timestamp of the last measurement from the
	// reference.
	RefTime time.Time

	// SystemTimeOffset is the current offset in seconds; positive means
	// the system clock is ahead of the reference.
	SystemTimeOffset float64

	// LastOffset is the offset at the last clock update, in seconds.
	LastOffset float64

	// RootDelay is the accumulated round-trip delay, in seconds.
	RootDelay float64

	// RootDispersion is the accumulated dispersion, in seconds.
	RootDispersion float64

	// LeapStatus is chronyd's leap indicator.
	LeapStatus string
}

// Synced reports whether chronyd currently disciplines the clock.
func (t *Tracking) Synced() bool {
	if t == nil {
		return false
	}
	return t.LeapStatus != LeapNotSynchronised &&
		t.Stratum > UnsyncedStratum && t.Stratum < MaxStratum
}

// Controller reads state from and issues commands to a running chronyd over
// its control socket.
type Controller interface {
	// Tracking returns chronyd's current tracking report.
	Tracking(ctx context.Context) (*Tracking, error)

	// Sources returns the configured sources and their measurement state.
	Sources(ctx context.Context) ([]Source, error)

	// MakeStep asks chronyd to correct the clock with an immediate step.
	MakeStep(ctx context.Context) error
}

// chronycBinary is the control client shipped with the chrony package.
const chronycBinary = "chronyc"

// trackingFieldCount is the number of CSV columns `chronyc -c tracking`
// emits.
const trackingFieldCount = 14

// sourcesFieldCount is the number of CSV columns `chronyc -c sources` emits.
const sourcesFieldCount = 10

// chronyc is the production Controller. It shells out to chronyc, which
// speaks chrony's native command protocol over the local Unix control socket
// — the platform never reimplements that protocol.
type chronyc struct {
	runner CommandRunner
	socket string
}

// NewController returns a Controller that reaches chronyd through the given
// control socket. A nil runner uses os/exec.
func NewController(socket string, runner CommandRunner) Controller {
	if runner == nil {
		runner = execRunner{}
	}
	return &chronyc{runner: runner, socket: socket}
}

// args builds the chronyc argument vector for a command. `-c` selects CSV
// output and `-n` suppresses reverse DNS so a broken resolver never stalls a
// status poll.
func (c *chronyc) args(command string) []string {
	args := make([]string, 0, 6)
	args = append(args, "-c", "-n")
	if c.socket != "" {
		args = append(args, "-h", c.socket)
	}
	return append(args, command)
}

// run executes a chronyc command and returns its output.
func (c *chronyc) run(ctx context.Context, command string) (string, error) {
	out, err := c.runner.Run(ctx, chronycBinary, c.args(command)...)
	if err != nil {
		return "", ErrControlUnavailable{Command: command, Output: string(out), Cause: err}
	}
	return string(out), nil
}

// Tracking returns chronyd's current tracking report.
func (c *chronyc) Tracking(ctx context.Context) (*Tracking, error) {
	out, err := c.run(ctx, "tracking")
	if err != nil {
		return nil, err
	}
	return parseTracking(out)
}

// Sources returns the configured sources and their measurement state.
func (c *chronyc) Sources(ctx context.Context) ([]Source, error) {
	out, err := c.run(ctx, "sources")
	if err != nil {
		return nil, err
	}
	return parseSources(out)
}

// MakeStep asks chronyd to correct the clock with an immediate step.
func (c *chronyc) MakeStep(ctx context.Context) error {
	_, err := c.run(ctx, "makestep")
	return err
}

// newCSVReader returns a CSV reader configured for chronyc output: variable
// field counts are validated per record so a malformed line produces a typed
// error instead of a silent short read.
func newCSVReader(payload string) *csv.Reader {
	reader := csv.NewReader(strings.NewReader(payload))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	return reader
}

// parseTracking converts `chronyc -c tracking` CSV into a Tracking report.
func parseTracking(payload string) (*Tracking, error) {
	records, err := newCSVReader(payload).ReadAll()
	if err != nil {
		return nil, ErrMalformedControlOutput{
			Command: "tracking",
			Line:    strings.TrimSpace(payload),
			Want:    trackingFieldCount,
			Got:     0,
		}
	}
	if len(records) == 0 {
		return nil, ErrMalformedControlOutput{
			Command: "tracking",
			Line:    strings.TrimSpace(payload),
			Want:    trackingFieldCount,
			Got:     0,
		}
	}

	fields := records[0]
	if len(fields) < trackingFieldCount {
		return nil, ErrMalformedControlOutput{
			Command: "tracking",
			Line:    strings.Join(fields, ","),
			Want:    trackingFieldCount,
			Got:     len(fields),
		}
	}

	return &Tracking{
		ReferenceID:      fields[0],
		ReferenceName:    fields[1],
		Stratum:          parseUint32(fields[2]),
		RefTime:          parseUnixFloat(fields[3]),
		SystemTimeOffset: parseFloat(fields[4]),
		LastOffset:       parseFloat(fields[5]),
		RootDelay:        parseFloat(fields[10]),
		RootDispersion:   parseFloat(fields[11]),
		LeapStatus:       strings.TrimSpace(fields[13]),
	}, nil
}

// parseSources converts `chronyc -c sources` CSV into Source records.
func parseSources(payload string) ([]Source, error) {
	records, err := newCSVReader(payload).ReadAll()
	if err != nil {
		return nil, ErrMalformedControlOutput{
			Command: "sources",
			Line:    strings.TrimSpace(payload),
			Want:    sourcesFieldCount,
			Got:     0,
		}
	}

	sources := make([]Source, 0, len(records))
	for _, fields := range records {
		if len(fields) == 0 || (len(fields) == 1 && strings.TrimSpace(fields[0]) == "") {
			continue
		}
		if len(fields) < sourcesFieldCount {
			return nil, ErrMalformedControlOutput{
				Command: "sources",
				Line:    strings.Join(fields, ","),
				Want:    sourcesFieldCount,
				Got:     len(fields),
			}
		}

		reach := parseUint32(fields[5])
		sources = append(sources, Source{
			Mode:          parseSourceMode(strings.TrimSpace(fields[0])),
			State:         parseSourceState(strings.TrimSpace(fields[1])),
			Address:       strings.TrimSpace(fields[2]),
			Stratum:       parseUint32(fields[3]),
			PollSeconds:   pollIntervalSeconds(fields[4]),
			Reach:         reach,
			LastRxSeconds: parseInt64(fields[6]),
			OffsetSeconds: parseFloat(fields[7]),
			Reachable:     reach != 0,
		})
	}

	return sources, nil
}

// pollIntervalSeconds converts chrony's log2 poll interval to seconds.
func pollIntervalSeconds(raw string) uint32 {
	exponent, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || exponent < 0 || exponent > 31 {
		return 0
	}
	return uint32(1) << uint(exponent)
}

// parseUint32 parses a decimal field, yielding 0 on malformed input. chronyd
// emits well-formed numerics; a bad field means the column is absent for this
// source, which is semantically zero.
func parseUint32(raw string) uint32 {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(value)
}

// parseInt64 parses a signed decimal field, yielding 0 on malformed input.
func parseInt64(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// parseFloat parses a float field, yielding 0 on malformed input.
func parseFloat(raw string) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return value
}

// parseUnixFloat parses chrony's fractional UNIX timestamp. A zero or
// malformed value yields the zero time, which callers render as "never".
func parseUnixFloat(raw string) time.Time {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	whole, fraction := int64(seconds), seconds-float64(int64(seconds))
	return time.Unix(whole, int64(fraction*float64(time.Second))).UTC()
}
