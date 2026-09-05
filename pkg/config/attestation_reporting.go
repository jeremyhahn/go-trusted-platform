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

package config

import (
	"fmt"
	"strings"
	"time"
)

// Caller-admission strategies for the node-side quote endpoints (#226).
//
// The strategy decides WHICH authenticated machine peers may ask this node
// for a TPM quote. It runs after the peer's certificate has chained to the
// configured anchors; it never substitutes for that check.
const (
	// CallerStrategyReportingServers admits only the identities configured
	// (or derived) as this node's reporting servers. It is the default and
	// the narrowest choice.
	CallerStrategyReportingServers = "reporting-servers"

	// CallerStrategyAnyAttested admits any peer whose own attestation is
	// currently verified and fresh. It is honoured only where attested-peer
	// evidence exists locally; elsewhere it refuses everyone.
	CallerStrategyAnyAttested = "any-attested"

	// CallerStrategyAllowlist admits an explicitly provisioned set of peer
	// identities. An empty list refuses everyone.
	CallerStrategyAllowlist = "allowlist"
)

// Defaults for the reporting service.
const (
	// DefaultReportingInterval is the collector refresh cycle (#226
	// requirement 5: 15 minutes, configurable).
	DefaultReportingInterval = 15 * time.Minute

	// DefaultReportingPort is the port a node's webservice serves the quote
	// endpoint on. Every shipped worker template listens on 9443.
	DefaultReportingPort = 9443

	// DefaultReportingTimeout bounds a single collection round-trip.
	DefaultReportingTimeout = 30 * time.Second

	// DefaultCallerStrategy is the strategy applied when none is configured.
	DefaultCallerStrategy = CallerStrategyReportingServers
)

// ReportingConfig configures the attestation reporting service: the
// control-plane collector that dials nodes for quotes, and the node-side
// admission policy that decides who may ask.
//
// Both halves live in the same section because roles are configuration, not
// binaries: the same platformd reads `attestation.reporting` whether it is
// the node being asked or the reporting server asking.
type ReportingConfig struct {
	// Enabled starts the collector on this node. A node that is only ever
	// asked for quotes leaves it false and configures Callers.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Interval is the refresh cycle. Zero selects DefaultReportingInterval.
	Interval time.Duration `yaml:"interval,omitempty" json:"interval,omitempty" mapstructure:"interval"`

	// TTL is how long a report is presented as fresh. Zero selects twice the
	// interval, and a value shorter than the interval is rejected: it would
	// mark every report stale before its replacement was due.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl"`

	// Collector configures how the reporting server reaches nodes.
	Collector *CollectorConfig `yaml:"collector,omitempty" json:"collector,omitempty" mapstructure:"collector"`

	// Callers configures which machine peers this node admits to its quote
	// endpoints.
	Callers *CallerAdmissionConfig `yaml:"callers,omitempty" json:"callers,omitempty" mapstructure:"callers"`
}

// CollectorConfig configures the reporting server's outbound side.
type CollectorConfig struct {
	// Identity names the webservice whose key and certificate the collector
	// presents as its mTLS client identity. Empty selects the primary
	// webservice. The name must match a `webservices[].name` entry.
	Identity string `yaml:"identity,omitempty" json:"identity,omitempty" mapstructure:"identity"`

	// Port is the node webservice TLS port hosting the quote endpoint. Zero
	// selects DefaultReportingPort.
	Port int `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`

	// Timeout bounds one collection round-trip. Zero selects
	// DefaultReportingTimeout.
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`

	// PCRs selects the PCR indices the node is asked to quote. Empty asks
	// for the node's default manifest selection.
	PCRs []int `yaml:"pcrs,omitempty" json:"pcrs,omitempty" mapstructure:"pcrs"`
}

// CallerAdmissionConfig configures node-side admission to the
// quote-producing endpoints.
type CallerAdmissionConfig struct {
	// Strategy selects the admission strategy. Empty selects
	// DefaultCallerStrategy.
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty" mapstructure:"strategy"`

	// ReportingServers lists the TLS identities (certificate Common Name or
	// DNS SAN) of this node's reporting servers. Empty derives the set from
	// the ACME directory this node enrolled against.
	ReportingServers []string `yaml:"reporting-servers,omitempty" json:"reporting_servers,omitempty" mapstructure:"reporting-servers"`

	// Allowlist lists the peer identities admitted by the allowlist
	// strategy. It is consulted only when Strategy is "allowlist".
	Allowlist []string `yaml:"allowlist,omitempty" json:"allowlist,omitempty" mapstructure:"allowlist"`

	// CAFile is a PEM bundle of the certificate authorities a caller must
	// chain to. Empty selects the issuer chain of this node's own IDevID
	// certificate, which is the control plane that enrolled it.
	CAFile string `yaml:"ca-file,omitempty" json:"ca-file,omitempty" mapstructure:"ca-file"`
}

// ErrInvalidReportingInterval reports an interval or TTL that cannot work.
type ErrInvalidReportingInterval struct {
	Field  string
	Reason string
}

func (e ErrInvalidReportingInterval) Error() string {
	return fmt.Sprintf("config: attestation.reporting.%s: %s", e.Field, e.Reason)
}

// ErrInvalidCallerStrategy reports an unknown admission strategy.
type ErrInvalidCallerStrategy struct {
	Strategy string
}

func (e ErrInvalidCallerStrategy) Error() string {
	return fmt.Sprintf("config: attestation.reporting.callers.strategy %q is not one of %s, %s, %s",
		e.Strategy, CallerStrategyReportingServers, CallerStrategyAnyAttested, CallerStrategyAllowlist)
}

// ErrInvalidCollectorPort reports a port outside the TCP range.
type ErrInvalidCollectorPort struct {
	Port int
}

func (e ErrInvalidCollectorPort) Error() string {
	return fmt.Sprintf("config: attestation.reporting.collector.port %d is not in 1-65535", e.Port)
}

// Validate checks the section. A nil receiver is valid: the feature is
// simply off.
func (r *ReportingConfig) Validate() error {
	if r == nil {
		return nil
	}
	if r.Interval < 0 {
		return ErrInvalidReportingInterval{Field: "interval", Reason: "must not be negative"}
	}
	if r.TTL < 0 {
		return ErrInvalidReportingInterval{Field: "ttl", Reason: "must not be negative"}
	}
	if r.TTL > 0 && r.TTL < r.EffectiveInterval() {
		return ErrInvalidReportingInterval{Field: "ttl",
			Reason: "must be at least the refresh interval; a shorter TTL marks every report stale before its replacement is due"}
	}
	if r.Collector != nil {
		if err := r.Collector.Validate(); err != nil {
			return err
		}
	}
	if r.Callers != nil {
		if err := r.Callers.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// EffectiveInterval returns the refresh cycle with the default applied.
func (r *ReportingConfig) EffectiveInterval() time.Duration {
	if r == nil || r.Interval <= 0 {
		return DefaultReportingInterval
	}
	return r.Interval
}

// EffectiveTTL returns the freshness window with the default applied.
func (r *ReportingConfig) EffectiveTTL() time.Duration {
	if r == nil || r.TTL <= 0 {
		return 2 * r.EffectiveInterval()
	}
	return r.TTL
}

// Validate checks the collector settings.
func (c *CollectorConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Port < 0 || c.Port > 65535 {
		return ErrInvalidCollectorPort{Port: c.Port}
	}
	if c.Timeout < 0 {
		return ErrInvalidReportingInterval{Field: "collector.timeout", Reason: "must not be negative"}
	}
	for _, idx := range c.PCRs {
		if idx < MinPCRIndex || idx > MaxPCRIndex {
			return ErrInvalidPCR{Index: idx, Min: MinPCRIndex, Max: MaxPCRIndex}
		}
	}
	return nil
}

// EffectivePort returns the node quote port with the default applied.
func (c *CollectorConfig) EffectivePort() int {
	if c == nil || c.Port == 0 {
		return DefaultReportingPort
	}
	return c.Port
}

// EffectiveTimeout returns the round-trip bound with the default applied.
func (c *CollectorConfig) EffectiveTimeout() time.Duration {
	if c == nil || c.Timeout <= 0 {
		return DefaultReportingTimeout
	}
	return c.Timeout
}

// Validate checks the admission settings. Only the strategy name is
// validated here: an empty allowlist is a runtime refusal, not a startup
// failure, because a node must come up (and keep answering operators) even
// when its machine-caller policy admits nobody.
func (c *CallerAdmissionConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.EffectiveStrategy() {
	case CallerStrategyReportingServers, CallerStrategyAnyAttested, CallerStrategyAllowlist:
		return nil
	default:
		return ErrInvalidCallerStrategy{Strategy: c.Strategy}
	}
}

// EffectiveStrategy returns the strategy with the default applied and
// whitespace and case normalised.
func (c *CallerAdmissionConfig) EffectiveStrategy() string {
	if c == nil {
		return DefaultCallerStrategy
	}
	s := strings.ToLower(strings.TrimSpace(c.Strategy))
	if s == "" {
		return DefaultCallerStrategy
	}
	return s
}
