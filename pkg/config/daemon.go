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
	"net"
	"net/netip"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// The `daemon:` section of the platform configuration: where platformd's
// inbound transports bind. It exists because of the 2026-08-26 ruling
// (conventions/configuration.md §3): no bind address is hardcoded, every
// one is configurable through the file, the environment and flags under
// the precedence flags > env > file > defaults, and the literal appears
// only in the defaults layer.
//
// The defaults layer is LOOPBACK for every transport (#552, #93). The
// platform's inbound API is a control surface, and a node must never find
// itself serving it on every interface because nobody said otherwise;
// exposing a transport is an explicit operator choice, made per transport.
//
//	daemon:
//	  rest: {bind-host: 127.0.0.1, port: 8443}
//	  grpc: {bind-host: 127.0.0.1, port: 10443}
//	  quic: {bind-host: 127.0.0.1, port: 9444}
//	  mcp:  {bind-host: 127.0.0.1, port: 9445}
//
// Environment: PLATFORMD_DAEMON_<TRANSPORT>_BIND_HOST / _PORT. Flags:
// --<transport>-bind-host / --<transport>-port on `platformd serve`.

// LoopbackBindHost is the defaults-layer bind host of every daemon transport.
const LoopbackBindHost = "127.0.0.1"

// Canonical daemon transport ports; the defaults layer, overridable by
// file, env and flag.
const (
	DefaultRESTPort = 8443
	DefaultGRPCPort = 10443
	DefaultQUICPort = 9444
	DefaultMCPPort  = 9445
)

// Transport names as they appear in config keys, flags and errors.
const (
	TransportREST = "rest"
	TransportGRPC = "grpc"
	TransportQUIC = "quic"
	TransportMCP  = "mcp"
)

// daemonKeyPrefix roots every listener key in the `daemon:` section.
const daemonKeyPrefix = "daemon"

// Listener is one inbound transport's bind host and port.
type Listener struct {
	// BindHost is the address the transport listens on. Empty means the
	// unspecified address (every interface); an IP literal or a hostname
	// binds that address. It never carries a port.
	BindHost string `yaml:"bind-host" json:"bind_host" mapstructure:"bind-host"`
	// Port is the transport's TCP or UDP port.
	Port int `yaml:"port" json:"port" mapstructure:"port"`
}

// Address returns the host:port the listener binds, in the form
// net.Listen accepts (IPv6 literals bracketed, an empty host as ":port").
func (l Listener) Address() string {
	return net.JoinHostPort(l.BindHost, fmt.Sprintf("%d", l.Port))
}

// Network narrows a base network ("tcp" or "udp") to the address family of
// BindHost when the host is an IP literal, so a listener asked for "::1" is
// opened as tcp6 and one asked for "127.0.0.1" as tcp4. A hostname or an
// empty host keeps the base network and lets the resolver decide.
func (l Listener) Network(base string) string {
	addr, err := netip.ParseAddr(l.BindHost)
	if err != nil {
		return base
	}
	if addr.Is4() {
		return base + "4"
	}
	return base + "6"
}

// validate checks the listener for transport, so an error names the
// section that carries the bad value.
func (l Listener) validate(transport string) error {
	if l.Port < 1 || l.Port > 65535 {
		return &ErrInvalidListenerPort{Transport: transport, Port: l.Port}
	}
	if l.BindHost == "" {
		return nil
	}
	if strings.ContainsAny(l.BindHost, " \t[]") || strings.Count(l.BindHost, ":") == 1 {
		// A space is never valid; brackets and a lone colon mean the
		// operator wrote host:port into a host-only field.
		return &ErrInvalidBindHost{Transport: transport, Host: l.BindHost}
	}
	return nil
}

// DaemonListeners is the `daemon:` section: one listener per transport.
type DaemonListeners struct {
	REST Listener `yaml:"rest" json:"rest" mapstructure:"rest"`
	GRPC Listener `yaml:"grpc" json:"grpc" mapstructure:"grpc"`
	QUIC Listener `yaml:"quic" json:"quic" mapstructure:"quic"`
	MCP  Listener `yaml:"mcp" json:"mcp" mapstructure:"mcp"`
}

// DefaultDaemonListeners is the defaults layer: loopback on the canonical
// ports for every transport.
func DefaultDaemonListeners() DaemonListeners {
	return DaemonListeners{
		REST: Listener{BindHost: LoopbackBindHost, Port: DefaultRESTPort},
		GRPC: Listener{BindHost: LoopbackBindHost, Port: DefaultGRPCPort},
		QUIC: Listener{BindHost: LoopbackBindHost, Port: DefaultQUICPort},
		MCP:  Listener{BindHost: LoopbackBindHost, Port: DefaultMCPPort},
	}
}

// Validate checks every listener and names the first transport in error.
func (d DaemonListeners) Validate() error {
	for _, item := range d.entries() {
		if err := item.listener.validate(item.transport); err != nil {
			return err
		}
	}
	return nil
}

// listenerEntry pairs a transport name with its listener for iteration
// in a fixed order.
type listenerEntry struct {
	transport string
	listener  Listener
}

func (d DaemonListeners) entries() []listenerEntry {
	return []listenerEntry{
		{TransportREST, d.REST},
		{TransportGRPC, d.GRPC},
		{TransportQUIC, d.QUIC},
		{TransportMCP, d.MCP},
	}
}

// bindHostKey and portKey are the viper keys of a transport's listener
// fields: daemon.<transport>.bind-host and daemon.<transport>.port.
func bindHostKey(transport string) string { return daemonKeyPrefix + "." + transport + ".bind-host" }
func portKey(transport string) string     { return daemonKeyPrefix + "." + transport + ".port" }

// flag names, derived from the transport so the three paths stay aligned.
func bindHostFlag(transport string) string { return transport + "-bind-host" }
func portFlag(transport string) string     { return transport + "-port" }

// SetDaemonListenerDefaults installs the defaults layer on v.
func SetDaemonListenerDefaults(v *viper.Viper) {
	for _, item := range DefaultDaemonListeners().entries() {
		v.SetDefault(bindHostKey(item.transport), item.listener.BindHost)
		v.SetDefault(portKey(item.transport), item.listener.Port)
	}
}

// BindDaemonListenerFlags registers --<transport>-bind-host and
// --<transport>-port on flags and binds each to its viper key, so a flag
// the operator passes wins and a flag left alone falls through to the
// environment, the file and the defaults. Registering twice is an error:
// pflag would panic on the duplicate.
func BindDaemonListenerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	for _, item := range DefaultDaemonListeners().entries() {
		hostFlag := bindHostFlag(item.transport)
		pFlag := portFlag(item.transport)
		if flags.Lookup(hostFlag) != nil {
			return &ErrFlagAlreadyBound{Flag: hostFlag}
		}
		if flags.Lookup(pFlag) != nil {
			return &ErrFlagAlreadyBound{Flag: pFlag}
		}
		flags.String(hostFlag, item.listener.BindHost,
			strings.ToUpper(item.transport)+" bind host (config daemon."+item.transport+".bind-host)")
		flags.Int(pFlag, item.listener.Port,
			strings.ToUpper(item.transport)+" port (config daemon."+item.transport+".port)")
		if err := v.BindPFlag(bindHostKey(item.transport), flags.Lookup(hostFlag)); err != nil {
			return &WrappedError{Msg: "config: bind " + hostFlag, Err: err}
		}
		if err := v.BindPFlag(portKey(item.transport), flags.Lookup(pFlag)); err != nil {
			return &WrappedError{Msg: "config: bind " + pFlag, Err: err}
		}
	}
	return nil
}

// BindDaemonListenerEnv turns on the environment layer for v under prefix:
// PREFIX_DAEMON_<TRANSPORT>_BIND_HOST and PREFIX_DAEMON_<TRANSPORT>_PORT.
// The replacer maps every key separator and hyphen to an underscore, so
// the same rule reaches every other key in the file as well.
func BindDaemonListenerEnv(v *viper.Viper, prefix string) {
	v.SetEnvPrefix(prefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
}

// ResolveDaemonListeners reads every listener field through v, which
// applies the precedence flags > env > file > defaults per field, and
// validates the result. Each field is read on its own so a file that sets
// only a port keeps the default host, and a flag that names one transport
// changes nothing else.
func ResolveDaemonListeners(v *viper.Viper) (DaemonListeners, error) {
	read := func(transport string) Listener {
		return Listener{
			BindHost: v.GetString(bindHostKey(transport)),
			Port:     v.GetInt(portKey(transport)),
		}
	}
	d := DaemonListeners{
		REST: read(TransportREST),
		GRPC: read(TransportGRPC),
		QUIC: read(TransportQUIC),
		MCP:  read(TransportMCP),
	}
	if err := d.Validate(); err != nil {
		return DaemonListeners{}, err
	}
	return d, nil
}

// ErrInvalidListenerPort reports a port outside 1..65535.
type ErrInvalidListenerPort struct {
	Transport string
	Port      int
}

// Error implements the error interface.
func (e *ErrInvalidListenerPort) Error() string {
	return fmt.Sprintf("config: daemon.%s.port %d is not in 1..65535", e.Transport, e.Port)
}

// ErrInvalidBindHost reports a bind host that is not an address or a
// hostname — typically a host:port written into the host field.
type ErrInvalidBindHost struct {
	Transport string
	Host      string
}

// Error implements the error interface.
func (e *ErrInvalidBindHost) Error() string {
	return fmt.Sprintf("config: daemon.%s.bind-host %q is not an IP address or hostname", e.Transport, e.Host)
}

// ErrFlagAlreadyBound reports a listener flag registered twice.
type ErrFlagAlreadyBound struct {
	Flag string
}

// Error implements the error interface.
func (e *ErrFlagAlreadyBound) Error() string {
	return "config: flag --" + e.Flag + " is already registered"
}
