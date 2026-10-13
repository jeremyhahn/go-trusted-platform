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

// Package ntp owns the platform's time-synchronization surface. The platform
// does not implement the NTP protocol: chrony runs as a packaged OpenRC
// service and this package renders its configuration, manages its lifecycle,
// polls its control socket for sync state, and exposes that state to the
// multi-protocol API.
//
// Time is a trust primitive here. TPM attestation freshness, ACME (RFC 8555)
// issuance, DANE/DNSSEC signature windows, and JWT exp/nbf all silently
// misbehave on a node whose clock has drifted, so a node that cannot prove it
// is synchronized is flagged in health status rather than left unnoticed.
//
// Following the platform's explicit-configuration convention, an absent
// `ntp:` section means platformd never touches chrony at all.
package ntp

import (
	"net/netip"
	"strings"
	"time"
)

// Mode selects whether a node serves NTP to peers, consumes it from
// upstream, or both.
type Mode string

const (
	// ModeServe serves time to the configured listen networks only.
	ModeServe Mode = "serve"

	// ModeConsume synchronizes from upstream sources only.
	ModeConsume Mode = "consume"

	// ModeBoth consumes from upstream and serves the result to peers. This
	// is the control-plane role.
	ModeBoth Mode = "both"
)

// Serves reports whether the mode makes the node an NTP server.
func (m Mode) Serves() bool { return m == ModeServe || m == ModeBoth }

// Consumes reports whether the mode makes the node an NTP client.
func (m Mode) Consumes() bool { return m == ModeConsume || m == ModeBoth }

// TimeoutAction selects what happens when the startup sync gate expires.
type TimeoutAction string

const (
	// ActionWarnAndContinue boots the node but flags it time-unsynced in
	// health status so fleet monitoring surfaces it. This is the default.
	ActionWarnAndContinue TimeoutAction = "warn-and-continue"

	// ActionFailStartup aborts platformd startup with ErrSyncTimeout.
	ActionFailStartup TimeoutAction = "fail-startup"
)

// DefaultGateTimeout is the startup gate deadline applied when
// startup-gate.timeout is omitted.
const DefaultGateTimeout = 120 * time.Second

// DefaultLocalStratum is the orphan-mode stratum applied when
// serve.local-stratum is omitted. Stratum 10 keeps a self-referencing
// control plane clearly below any real upstream chain.
const DefaultLocalStratum = 10

// DefaultNTSKEPort is the NTS-KE TCP port applied when serve.nts.port is
// omitted: the IANA-assigned RFC 8915 port.
const DefaultNTSKEPort = 4460

// Config is the `ntp:` configuration section. A nil *Config means the
// section is absent and platformd leaves chrony completely alone.
type Config struct {
	// Enabled gates the whole subsystem. A present-but-disabled section is
	// treated exactly like an absent one.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Mode selects serve, consume, or both.
	Mode Mode `yaml:"mode" json:"mode" mapstructure:"mode"`

	// Consume configures upstream synchronization and the startup gate.
	Consume *ConsumeConfig `yaml:"consume,omitempty" json:"consume,omitempty" mapstructure:"consume"`

	// Serve configures the server side (allow-list, orphan stratum, NTS).
	Serve *ServeConfig `yaml:"serve,omitempty" json:"serve,omitempty" mapstructure:"serve"`

	// RTC configures hardware-clock write-back.
	RTC *RTCConfig `yaml:"rtc,omitempty" json:"rtc,omitempty" mapstructure:"rtc"`
}

// ConsumeConfig describes how the node obtains time from upstream.
type ConsumeConfig struct {
	// Upstream lists the servers and pools chronyd polls, in order.
	Upstream []UpstreamSource `yaml:"upstream,omitempty" json:"upstream,omitempty" mapstructure:"upstream"`

	// StartupGate blocks platform bring-up until the clock is trustworthy.
	StartupGate *StartupGate `yaml:"startup-gate,omitempty" json:"startup_gate,omitempty" mapstructure:"startup-gate"`

	// OrphanFallback keeps the local clock usable as a last-resort
	// reference when no upstream is reachable. Only meaningful on a node
	// that also serves time.
	OrphanFallback bool `yaml:"orphan-fallback" json:"orphan_fallback" mapstructure:"orphan-fallback"`
}

// UpstreamSource is one `server` or `pool` line in chrony.conf.
type UpstreamSource struct {
	// Address is the host name or IP of the upstream.
	Address string `yaml:"address" json:"address" mapstructure:"address"`

	// Pool renders the source as a chrony `pool` directive (a name that
	// resolves to several addresses) instead of `server`.
	Pool bool `yaml:"pool,omitempty" json:"pool,omitempty" mapstructure:"pool"`

	// Prefer marks this source as preferred over the others.
	Prefer bool `yaml:"prefer,omitempty" json:"prefer,omitempty" mapstructure:"prefer"`

	// IBurst sends a fast initial burst so the first sync is quick. This
	// is what turns a two-year clock error into a sub-minute correction.
	IBurst bool `yaml:"iburst,omitempty" json:"iburst,omitempty" mapstructure:"iburst"`

	// NTS requires RFC 8915 Network Time Security towards this source.
	// Internal control-plane sources set this; most public upstreams and
	// nearly every router cannot do NTS, so it is best-effort there.
	NTS bool `yaml:"nts,omitempty" json:"nts,omitempty" mapstructure:"nts"`
}

// StartupGate blocks platform bring-up until chronyd reports a synchronized
// clock, so TPM/CA initialization never runs against a bogus time.
type StartupGate struct {
	// BlockUntilSynced enables the gate.
	BlockUntilSynced bool `yaml:"block-until-synced" json:"block_until_synced" mapstructure:"block-until-synced"`

	// Timeout bounds how long the gate waits.
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`

	// OnTimeout selects warn-and-continue (default) or fail-startup.
	OnTimeout TimeoutAction `yaml:"on-timeout,omitempty" json:"on_timeout,omitempty" mapstructure:"on-timeout"`
}

// ServeConfig describes the server side of the node's time service.
type ServeConfig struct {
	// ListenNetworks is the explicit CIDR allow-list rendered as chrony
	// `allow` directives. It is never 0.0.0.0/0 or ::/0 — an open NTP
	// server is a reflection-amplification source.
	ListenNetworks []string `yaml:"listen-networks,omitempty" json:"listen_networks,omitempty" mapstructure:"listen-networks"`

	// LocalStratum is the stratum announced when the server is running on
	// its own clock (orphan mode).
	LocalStratum int `yaml:"local-stratum,omitempty" json:"local_stratum,omitempty" mapstructure:"local-stratum"`

	// NTS configures RFC 8915 Network Time Security for served time.
	NTS *NTSConfig `yaml:"nts,omitempty" json:"nts,omitempty" mapstructure:"nts"`
}

// NTSConfig carries the platform-CA-issued key material chronyd uses as an
// NTS-KE server. The URIs are resolved by the platform secrets engine before
// the service starts, so by the time the renderer runs these fields hold PEM
// material, not URIs.
type NTSConfig struct {
	// Enabled turns on the NTS-KE server.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// CertURI references the NTS server certificate (kms:// URI).
	CertURI string `yaml:"cert-uri,omitempty" json:"cert_uri,omitempty" mapstructure:"cert-uri"`

	// KeyURI references the NTS server private key (kms:// URI).
	KeyURI string `yaml:"key-uri,omitempty" json:"key_uri,omitempty" mapstructure:"key-uri"`

	// ServerNames are the DNS names NTS clients dial this node's NTS-KE
	// server as, and therefore the names the served certificate must be
	// valid for. RFC 8915 key establishment is TLS: chronyd on a client
	// verifies the certificate against the name in its own `server`
	// directive, so a node configured with `server cp.example.internal
	// nts` completes the handshake only if the control plane's
	// certificate carries that exact name.
	//
	// The node's own hostname and FQDN are always included by the
	// provisioner; this list adds the ROLE names clients use — on the
	// control plane, the `cp.<internal-domain>` alias every node's
	// ntp.consume.upstream points at.
	//
	// Names only. An IP address is rejected: platform certificates are
	// DNS-only by standing ruling, so an address here would produce a
	// certificate no client could validate.
	ServerNames []string `yaml:"server-names,omitempty" json:"server_names,omitempty" mapstructure:"server-names"`

	// Port is the TCP port chronyd's NTS-KE server listens on, rendered as
	// chrony's `ntsport`. The renewal sweep dials the same port to read the
	// certificate chronyd serves. 0 means DefaultNTSKEPort.
	Port int `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`
}

// NTSServerNames returns the extra DNS names the served NTS-KE certificate
// must carry, trimmed. Empty when NTS is not served or none are configured.
func (c *Config) NTSServerNames() []string {
	if !c.NTSServing() {
		return nil
	}
	names := make([]string, 0, len(c.Serve.NTS.ServerNames))
	for _, name := range c.Serve.NTS.ServerNames {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// RTCConfig controls hardware-clock write-back.
type RTCConfig struct {
	// WriteBack runs `hwclock --systohc` once the clock is confirmed
	// synchronized, so the next cold boot starts from a sane time even
	// before the network is up.
	WriteBack bool `yaml:"write-back" json:"write_back" mapstructure:"write-back"`
}

// Active reports whether platformd should manage chrony at all.
func (c *Config) Active() bool { return c != nil && c.Enabled }

// GateTimeout returns the effective startup gate deadline.
func (c *Config) GateTimeout() time.Duration {
	if c == nil || c.Consume == nil || c.Consume.StartupGate == nil ||
		c.Consume.StartupGate.Timeout <= 0 {
		return DefaultGateTimeout
	}
	return c.Consume.StartupGate.Timeout
}

// GateEnabled reports whether the startup gate should block bring-up.
func (c *Config) GateEnabled() bool {
	return c.Active() && c.Mode.Consumes() &&
		c.Consume != nil && c.Consume.StartupGate != nil &&
		c.Consume.StartupGate.BlockUntilSynced
}

// TimeoutAction returns the effective gate timeout policy.
func (c *Config) TimeoutAction() TimeoutAction {
	if c == nil || c.Consume == nil || c.Consume.StartupGate == nil ||
		c.Consume.StartupGate.OnTimeout == "" {
		return ActionWarnAndContinue
	}
	return c.Consume.StartupGate.OnTimeout
}

// RTCWriteBack reports whether the hardware clock is updated after sync.
func (c *Config) RTCWriteBack() bool {
	return c != nil && c.RTC != nil && c.RTC.WriteBack
}

// LocalStratum returns the effective orphan-mode stratum.
func (c *Config) LocalStratum() int {
	if c == nil || c.Serve == nil || c.Serve.LocalStratum == 0 {
		return DefaultLocalStratum
	}
	return c.Serve.LocalStratum
}

// NTSKEPort returns the effective NTS-KE server port.
func (c *Config) NTSKEPort() int {
	if c == nil || c.Serve == nil || c.Serve.NTS == nil || c.Serve.NTS.Port == 0 {
		return DefaultNTSKEPort
	}
	return c.Serve.NTS.Port
}

// NTSServing reports whether the node runs an NTS-KE server.
func (c *Config) NTSServing() bool {
	return c.Active() && c.Mode.Serves() && c.Serve != nil &&
		c.Serve.NTS != nil && c.Serve.NTS.Enabled
}

// validTimeoutActions is the map-based membership test for on-timeout.
var validTimeoutActions = map[TimeoutAction]struct{}{
	ActionWarnAndContinue: {},
	ActionFailStartup:     {},
}

// validModes is the map-based membership test for mode.
var validModes = map[Mode]struct{}{
	ModeServe:   {},
	ModeConsume: {},
	ModeBoth:    {},
}

// unrestrictedNetworks are the prefixes that would turn the node into an open
// NTP reflector. They are rejected outright rather than warned about.
var unrestrictedNetworks = map[string]struct{}{
	"0.0.0.0/0": {},
	"::/0":      {},
}

// Validate checks the configuration for internal consistency. A disabled or
// absent section always validates: it does nothing.
func (c *Config) Validate() error {
	if c == nil {
		return ErrNilConfig{}
	}
	if !c.Enabled {
		return nil
	}

	if _, ok := validModes[c.Mode]; !ok {
		return ErrInvalidMode{Mode: string(c.Mode)}
	}

	if c.Mode.Consumes() {
		if err := c.validateConsume(); err != nil {
			return err
		}
	}

	if c.Mode.Serves() {
		if err := c.validateServe(); err != nil {
			return err
		}
	}

	return nil
}

// validateConsume checks the client side of the configuration.
func (c *Config) validateConsume() error {
	if c.Consume == nil {
		return ErrMissingConsumeSection{Mode: string(c.Mode)}
	}

	if len(c.Consume.Upstream) == 0 && !c.Consume.OrphanFallback {
		return ErrNoUpstream{}
	}

	for i, src := range c.Consume.Upstream {
		address := strings.TrimSpace(src.Address)
		if address == "" {
			return ErrEmptyUpstreamAddress{Index: i}
		}
		// chrony.conf is whitespace-delimited and line-oriented: an
		// address carrying whitespace or a comment marker would inject
		// additional directives.
		if strings.ContainsAny(address, " \t\r\n#") {
			return ErrInvalidUpstreamAddress{Address: src.Address}
		}
	}

	if gate := c.Consume.StartupGate; gate != nil {
		if gate.OnTimeout != "" {
			if _, ok := validTimeoutActions[gate.OnTimeout]; !ok {
				return ErrInvalidTimeoutAction{Action: string(gate.OnTimeout)}
			}
		}
		if gate.BlockUntilSynced && gate.Timeout < 0 {
			return ErrInvalidGateTimeout{Seconds: gate.Timeout.Seconds()}
		}
	}

	return nil
}

// validateServe checks the server side of the configuration.
func (c *Config) validateServe() error {
	if c.Serve == nil {
		return ErrMissingServeSection{Mode: string(c.Mode)}
	}

	if len(c.Serve.ListenNetworks) == 0 {
		return ErrNoListenNetworks{}
	}

	for _, network := range c.Serve.ListenNetworks {
		trimmed := strings.TrimSpace(network)
		if _, unrestricted := unrestrictedNetworks[trimmed]; unrestricted {
			return ErrUnrestrictedListenNetwork{Network: network}
		}
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return ErrInvalidListenNetwork{Network: network, Cause: err}
		}
		if prefix.Bits() == 0 {
			return ErrUnrestrictedListenNetwork{Network: network}
		}
	}

	if c.Serve.LocalStratum != 0 && (c.Serve.LocalStratum < 1 || c.Serve.LocalStratum > 15) {
		return ErrInvalidLocalStratum{Stratum: c.Serve.LocalStratum}
	}

	if nts := c.Serve.NTS; nts != nil && nts.Enabled {
		if strings.TrimSpace(nts.CertURI) == "" {
			return ErrMissingNTSMaterial{Field: "serve.nts.cert-uri"}
		}
		if strings.TrimSpace(nts.KeyURI) == "" {
			return ErrMissingNTSMaterial{Field: "serve.nts.key-uri"}
		}
		if err := validateNTSServerNames(nts.ServerNames); err != nil {
			return err
		}
		if nts.Port < 0 || nts.Port > 65535 {
			return ErrInvalidNTSKEPort{Port: nts.Port}
		}
	}

	return nil
}

// validateNTSServerNames checks the DNS names the served NTS-KE certificate
// must carry. They end up in a certificate's SANs, so they are validated
// here rather than discovered at issuance time by a CA rejecting them.
func validateNTSServerNames(names []string) error {
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return ErrInvalidNTSServerName{
				Name:   name,
				Reason: "empty entry",
			}
		}
		// An IP address here would produce a certificate carrying an IP
		// SAN, which the platform does not issue, or a DNS SAN no
		// resolver answers. Either way the client handshake fails, so it
		// is refused at configuration time.
		if _, err := netip.ParseAddr(trimmed); err == nil {
			return ErrInvalidNTSServerName{
				Name:   name,
				Reason: "an IP address; platform certificates are DNS-only, use the name that resolves to it",
			}
		}
		if strings.ContainsAny(trimmed, " \t\r\n#/:") {
			return ErrInvalidNTSServerName{
				Name:   name,
				Reason: "not a bare DNS name",
			}
		}
	}
	return nil
}
