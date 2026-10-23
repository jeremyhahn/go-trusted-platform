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

package nbd

import (
	"net"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

// ParamServer names the boot server's NBD listener, host:port, that a
// diskless-nbd node attaches its root from. It is read only from the signed
// UKI .cmdline, and only when platform_boot_model is diskless-nbd.
const ParamServer = "platform_nbd_server"

// cmdlineParams are the command-line keys ServerFromCmdline reads.
var cmdlineParams = map[string]bool{
	disklessroot.ParamBootModel: true,
	ParamServer:                 true,
}

// ServerAddr is the address of the boot server's NBD listener. There is no
// default port: the address always names one.
type ServerAddr struct {
	Host string
	Port uint16
}

// ParseServerAddr parses a platform_nbd_server value: an IP address or DNS
// name and a port, as host:port ([host]:port for IPv6).
func ParseServerAddr(value string) (ServerAddr, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return ServerAddr{}, ErrCmdline{Param: ParamServer, Reason: "must be host:port, got " + strconv.Quote(value)}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ServerAddr{}, ErrCmdline{Param: ParamServer, Reason: "must carry a port from 1 to 65535, got " + strconv.Quote(port)}
	}
	addr := ServerAddr{Host: host, Port: uint16(number)}
	if err := addr.Validate(); err != nil {
		return ServerAddr{}, err
	}
	return addr, nil
}

// Validate refuses an address with no usable host or a zero port.
func (a ServerAddr) Validate() error {
	if !validHost(a.Host) {
		return ErrCmdline{Param: ParamServer, Reason: "host must be an IP address or a DNS name, got " + strconv.Quote(a.Host)}
	}
	if a.Port == 0 {
		return ErrCmdline{Param: ParamServer, Reason: "must carry a port from 1 to 65535"}
	}
	return nil
}

// String is the address as host:port.
func (a ServerAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// Arg is the address as a kernel command-line parameter.
func (a ServerAddr) Arg() string {
	return ParamServer + "=" + a.String()
}

// ServerFromCmdline returns the NBD server address on a kernel command line.
// It reads platform_nbd_server only when platform_boot_model is
// diskless-nbd, and reports false for any other line. On a diskless-nbd line
// the address is required, may appear once, and must parse; the boot model
// itself may appear once on any line.
func ServerFromCmdline(cmdline string) (ServerAddr, bool, error) {
	values := map[string][]string{}
	for _, field := range strings.Fields(cmdline) {
		key, value, _ := strings.Cut(field, "=")
		if cmdlineParams[key] {
			values[key] = append(values[key], value)
		}
	}
	models := values[disklessroot.ParamBootModel]
	if len(models) > 1 {
		return ServerAddr{}, false, ErrCmdline{Param: disklessroot.ParamBootModel, Reason: "appears more than once on the kernel command line"}
	}
	if len(models) == 0 || models[0] != BootModel {
		return ServerAddr{}, false, nil
	}
	servers := values[ParamServer]
	if len(servers) == 0 {
		return ServerAddr{}, true, ErrCmdline{Param: ParamServer, Reason: "is required when " + disklessroot.ParamBootModel + " is " + BootModel}
	}
	if len(servers) > 1 {
		return ServerAddr{}, true, ErrCmdline{Param: ParamServer, Reason: "appears more than once on the kernel command line"}
	}
	addr, err := ParseServerAddr(servers[0])
	if err != nil {
		return ServerAddr{}, true, err
	}
	return addr, true, nil
}

// validHost reports whether host is an IP address or a DNS name, in the shape
// validIdentity accepts.
func validHost(host string) bool {
	return net.ParseIP(host) != nil || validIdentity(host)
}
