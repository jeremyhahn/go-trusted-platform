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
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrNilDriver is returned when Deps carries no Driver.
	ErrNilDriver = errors.New("nat64: driver is nil")

	// ErrNilController is returned when Deps carries no flow controller.
	ErrNilController = errors.New("nat64: flow controller is nil")

	// ErrNilOVSClient is returned when Deps carries no OVS client.
	ErrNilOVSClient = errors.New("nat64: ovs client is nil")

	// ErrAlreadyStarted is returned when Start is called on a running
	// service.
	ErrAlreadyStarted = errors.New("nat64: service already started")

	// ErrNotStarted is returned when an operation requires a running
	// service.
	ErrNotStarted = errors.New("nat64: service not started")

	// ErrEmptyBridge is returned when no OVS bridge is configured.
	ErrEmptyBridge = errors.New("nat64: bridge must be non-empty")

	// ErrEmptyInstance is returned when the Jool instance has no name.
	ErrEmptyInstance = errors.New("nat64: instance name must be non-empty")

	// ErrEmptyTranslatorPort is returned when no translator port is named.
	// Without it the table-27 gate has nowhere to send a translated frame,
	// which is the config-that-programs-nothing defect this service refuses
	// to become.
	ErrEmptyTranslatorPort = errors.New("nat64: translator port must be non-empty")

	// ErrNoPool4 is returned when the configuration declares no IPv4 pool.
	// Jool cannot allocate a translation without one.
	ErrNoPool4 = errors.New("nat64: at least one pool4 range is required")

	// ErrInvalidPool4Range is returned when a pool4 range is malformed or
	// its last address precedes its first.
	ErrInvalidPool4Range = errors.New("nat64: pool4 range is invalid")

	// ErrInvalidPortRange is returned when a pool4 port range is empty or
	// inverted.
	ErrInvalidPortRange = errors.New("nat64: pool4 port range start must be non-zero and below end")

	// ErrNoTranslatorOFPort is returned when the OVS port named as the
	// translator resolves to no OpenFlow port number.
	ErrNoTranslatorOFPort = errors.New("nat64: translator port has no OpenFlow port number")

	// ErrPool6Unreadable is returned when an instance's global
	// configuration carries no pool6 the driver can compare against.
	ErrPool6Unreadable = errors.New("nat64: the instance reports no pool6")

	// ErrInstanceVanished is returned when the driver reports no kernel
	// instance right after converging one, or a running service finds its
	// instance gone.
	ErrInstanceVanished = errors.New("nat64: the translator instance is not in the kernel")

	// ErrEmptyCommand is returned when a driver is asked to run an empty
	// command line.
	ErrEmptyCommand = errors.New("nat64: empty command")
)

// CommandError is a translator command that failed, carrying the exact
// argv and the tool's own output. An operator reading the log sees the
// command they can run by hand, which is the difference between a
// reproducible failure and a mystery.
type CommandError struct {
	// Cmd is the argv that was run.
	Cmd []string
	// Output is the tool's combined output, trimmed.
	Output string
	// Err is the exec error.
	Err error
}

// Error implements the error interface.
func (e *CommandError) Error() string {
	msg := strings.Join(e.Cmd, " ") + ": " + e.Err.Error()
	if e.Output != "" {
		msg += ": " + e.Output
	}
	return msg
}

// Unwrap implements errors.Unwrap.
func (e *CommandError) Unwrap() error { return e.Err }

// rfc6052Lengths are the prefix lengths RFC 6052 §2.2 defines for embedding
// an IPv4 address in an IPv6 prefix. Any other length has no defined
// embedding, so the translator would have nowhere to read the IPv4
// destination from.
var rfc6052Lengths = []int{32, 40, 48, 56, 64, 96}

// ErrInvalidNAT64Prefix reports a pool6 prefix that is not a usable RFC 6052
// translation prefix. It names the prefix and why it was refused rather than
// leaving the operator to guess which of the two rules it broke.
type ErrInvalidNAT64Prefix struct {
	// Prefix is the configured value, exactly as written.
	Prefix string
	// Reason is why it cannot be a translation prefix.
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidNAT64Prefix) Error() string {
	return "nat64: prefix " + e.Prefix + " is not a valid RFC 6052 translation prefix: " + e.Reason
}

// InvalidPrefixLength builds the refusal for a prefix whose length is not
// one RFC 6052 defines.
func InvalidPrefixLength(prefix string, bits int) *ErrInvalidNAT64Prefix {
	lengths := make([]string, 0, len(rfc6052Lengths))
	for _, l := range rfc6052Lengths {
		lengths = append(lengths, "/"+strconv.Itoa(l))
	}
	return &ErrInvalidNAT64Prefix{
		Prefix: prefix,
		Reason: "length /" + strconv.Itoa(bits) + " is not one of " + strings.Join(lengths, ", "),
	}
}

// ErrSessionTimeoutTooLow reports a session lifetime below the RFC 6146
// §3.5 minimum. The value is refused rather than quietly raised: an
// operator who wrote a number meant it, and a silently corrected timeout is
// a configuration that does not do what it says.
type ErrSessionTimeoutTooLow struct {
	// Field is the timeout's configuration key.
	Field string
	// Value is what was configured.
	Value time.Duration
	// Min is the RFC 6146 floor.
	Min time.Duration
}

// Error implements the error interface.
func (e *ErrSessionTimeoutTooLow) Error() string {
	return "nat64: session timeout " + e.Field + "=" + e.Value.String() +
		" is below the RFC 6146 minimum of " + e.Min.String()
}

// ErrNAT64PoolOverlap reports a pool4 range that overlaps an address range
// the NAT44 service already allocates from. Two independent translators
// handing out the same address and port produce a collision no packet
// capture explains, so the overlap is refused at configuration time.
type ErrNAT64PoolOverlap struct {
	// Pool is the nat64 pool4 range, as written.
	Pool string
	// Conflict is the NAT44 range it overlaps, as written.
	Conflict string
	// Uplink names the NAT44 uplink the conflicting range belongs to.
	Uplink string
}

// Error implements the error interface.
func (e *ErrNAT64PoolOverlap) Error() string {
	msg := "nat64: pool4 range " + e.Pool + " overlaps NAT44 pool " + e.Conflict
	if e.Uplink != "" {
		msg += " on uplink " + e.Uplink
	}
	return msg
}

// ErrNAT64ModuleUnavailable reports that the kernel translator is not
// usable: the module is not loaded, the tooling is absent, or the instance
// could not be created. The section is refused rather than started, so a
// kernel upgrade that outruns the module package shows up as a refused
// service instead of silent pass-through.
type ErrNAT64ModuleUnavailable struct {
	// Instance is the Jool instance the service tried to program.
	Instance string
	// Err is what the driver reported.
	Err error
}

// Error implements the error interface.
func (e *ErrNAT64ModuleUnavailable) Error() string {
	return "nat64: kernel translator unavailable for instance " + e.Instance + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *ErrNAT64ModuleUnavailable) Unwrap() error { return e.Err }

// ErrInvalidClientZone reports a client zone entry the divert cannot match.
type ErrInvalidClientZone struct {
	// Index is the entry's position in client-zones.
	Index int
	// Reason is the rule it broke.
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidClientZone) Error() string {
	return "nat64: client-zones[" + strconv.Itoa(e.Index) + "]: " + e.Reason
}

// OpError is a failed operation against the kernel translator or the
// datapath.
type OpError struct {
	// Op is the operation that failed ("install", "delete", "apply",
	// "resolve-port", "stats").
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string {
	return "nat64: " + e.Op + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *OpError) Unwrap() error { return e.Err }

// ErrTranslatorPortMAC is returned when the translator port reports no
// usable MAC address. The hand-off rewrites each frame's destination to it;
// without it the kernel drops the frame as addressed to another host.
type ErrTranslatorPortMAC struct {
	Port string
	MAC  string
}

func (e *ErrTranslatorPortMAC) Error() string {
	return "nat64: translator port " + strconv.Quote(e.Port) + " reports no usable MAC (" + strconv.Quote(e.MAC) + ")"
}

// ErrRollbackIncomplete reports a failed start whose rollback also failed:
// Cause is why the start failed, Rollback what could not be undone.
type ErrRollbackIncomplete struct {
	Cause    error
	Rollback error
}

func (e *ErrRollbackIncomplete) Error() string {
	return e.Cause.Error() + " (rollback incomplete: " + e.Rollback.Error() + ")"
}

// Unwrap exposes both the cause and the rollback failure.
func (e *ErrRollbackIncomplete) Unwrap() []error { return []error{e.Cause, e.Rollback} }

// ErrPool4TooLarge is returned when pool4 names more addresses than
// MaxPool4Addresses.
type ErrPool4TooLarge struct {
	Addresses uint64
	Max       uint64
}

func (e *ErrPool4TooLarge) Error() string {
	return "nat64: pool4 names " + strconv.FormatUint(e.Addresses, 10) +
		" addresses, more than the " + strconv.FormatUint(e.Max, 10) + " allowed"
}
