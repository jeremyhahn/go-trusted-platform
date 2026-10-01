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

// Package process runs gatewayd's services as separate, privilege-separated
// child processes (#557, ruling R14). One binary, many processes: OpenRC
// starts `gatewayd serve`, which is the supervisor, and the supervisor spawns
// a `gatewayd service run <process>` child per process, each with only the
// capabilities its class needs, its own cgroup v2 leaf, no_new_privs set, and
// an unprivileged uid for the classes that never touch the kernel.
package process

import (
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

// Class is a privilege class. There are two, and the split is the whole
// point of the model: the code that programs the kernel takes no untrusted
// input, and the code that parses untrusted input cannot program the kernel.
type Class string

const (
	// ClassKernel programs the datapath: OVSDB/OpenFlow, nftables, netlink
	// routes, XFRM and WireGuard links. It holds CAP_NET_ADMIN and reads
	// nothing off the wire.
	ClassKernel Class = "kernel"
	// ClassParser terminates untrusted input — BGP updates, HTTP requests,
	// DHCP/PXE packets, VPN admission. It runs unprivileged and reaches the
	// kernel only through the datapath process's narrow IPC surface.
	ClassParser Class = "parser"
)

// Definition is one child process: which services it hosts and how much
// privilege it is allowed to keep.
type Definition struct {
	// Name is the process name, the argument to `gatewayd service run`.
	Name string
	// Class is the privilege class.
	Class Class
	// Services are the gateway service constants this process hosts, in
	// gateway start order.
	Services []string
	// Capabilities are the capabilities the process keeps: its ambient set
	// at exec and the only ones left in its bounding set afterwards.
	// Everything else is dropped.
	Capabilities []uintptr
	// MemoryMax is the cgroup v2 memory.max in bytes; 0 leaves it unset.
	MemoryMax int64
	// CPUMax is the cgroup v2 cpu.max value ("200000 100000" is two cores);
	// empty leaves it unset.
	CPUMax string
	// Unprivileged reports whether the child drops to the configured
	// service uid. Kernel-programming processes stay root with a bounding
	// set of Capabilities; parsers do not stay root at all.
	Unprivileged bool
}

// definitions is the process table. It is the one place a service's class,
// capabilities and limits are decided; the supervisor, the child command and
// the operator documentation all read it rather than repeating the mapping.
//
// The refused sections (overlay, edge, dhcp, pxe, management-vpn) are placed
// too: their refusal belongs to the child that would host them, so an
// operator who enables one still gets that section's own ErrServiceUnavailable
// rather than a supervisor that cannot place it.
var definitions = []Definition{
	{
		Name:  "datapath",
		Class: ClassKernel,
		Services: []string{
			gateway.ServiceFirewall,
			gateway.ServiceNAT,
			gateway.ServiceLoadBalancer,
			gateway.ServiceNAT64,
			gateway.ServiceHostFW,
			gateway.ServiceTunnels,
			gateway.ServiceOverlay,
		},
		Capabilities: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW},
		MemoryMax:    512 << 20,
		CPUMax:       "200000 100000",
	},
	{
		Name:         "routing",
		Class:        ClassParser,
		Services:     []string{gateway.ServiceTransit},
		Capabilities: []uintptr{unix.CAP_NET_BIND_SERVICE},
		MemoryMax:    512 << 20,
		CPUMax:       "100000 100000",
		Unprivileged: true,
	},
	{
		Name:         "proxy",
		Class:        ClassParser,
		Services:     []string{gateway.ServiceProxy},
		Capabilities: []uintptr{unix.CAP_NET_BIND_SERVICE},
		MemoryMax:    1 << 30,
		CPUMax:       "200000 100000",
		Unprivileged: true,
	},
	{
		Name:         "provisioning",
		Class:        ClassParser,
		Services:     []string{gateway.ServiceDHCP, gateway.ServicePXE, gateway.ServiceEdge},
		Capabilities: []uintptr{unix.CAP_NET_BIND_SERVICE},
		MemoryMax:    256 << 20,
		CPUMax:       "100000 100000",
		Unprivileged: true,
	},
	{
		Name:         "vpn",
		Class:        ClassParser,
		Services:     []string{gateway.ServiceManagementVPN},
		MemoryMax:    256 << 20,
		CPUMax:       "100000 100000",
		Unprivileged: true,
	},
}

// byService indexes the table; built once, read-only afterwards.
var byService = func() map[string]Definition {
	index := make(map[string]Definition)
	for _, def := range definitions {
		for _, service := range def.Services {
			index[service] = def
		}
	}
	return index
}()

// byName indexes the table by process name.
var byName = func() map[string]Definition {
	index := make(map[string]Definition, len(definitions))
	for _, def := range definitions {
		index[def.Name] = def
	}
	return index
}()

// DefinitionForService returns the process that hosts a gateway service.
// Every service constant the gateway can enable is in the table; one that is
// not is a programming error the caller surfaces rather than places by
// default.
func DefinitionForService(service string) (Definition, error) {
	def, ok := byService[service]
	if !ok {
		return Definition{}, &ErrServiceUnplaced{Service: service}
	}
	return def, nil
}

// DefinitionByName returns a process definition by process name.
func DefinitionByName(name string) (Definition, error) {
	def, ok := byName[name]
	if !ok {
		return Definition{}, &ErrUnknownProcess{Process: name}
	}
	return def, nil
}

// Definitions returns the process table in declaration order.
func Definitions() []Definition {
	out := make([]Definition, len(definitions))
	copy(out, definitions)
	return out
}

// ServicesFor returns the subset of enabled services this process hosts, in
// the definition's order. It is what the child registers.
func (d Definition) ServicesFor(enabled []string) []string {
	want := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		want[name] = true
	}
	var out []string
	for _, service := range d.Services {
		if want[service] {
			out = append(out, service)
		}
	}
	return out
}

// Processes returns the processes needed to host the enabled services, in
// table order, each carrying only the services that are enabled.
func Processes(enabled []string) ([]Definition, error) {
	needed := map[string]bool{}
	for _, service := range enabled {
		def, err := DefinitionForService(service)
		if err != nil {
			return nil, err
		}
		needed[def.Name] = true
	}
	var out []Definition
	for _, def := range definitions {
		if !needed[def.Name] {
			continue
		}
		def.Services = def.ServicesFor(enabled)
		out = append(out, def)
	}
	return out, nil
}

// BoundingDrops returns the capabilities to drop from the bounding set so
// only the definition's capabilities remain, in ascending order.
func (d Definition) BoundingDrops() []uintptr {
	keep := make(map[uintptr]bool, len(d.Capabilities))
	for _, capability := range d.Capabilities {
		keep[capability] = true
	}
	var drops []uintptr
	for capability := uintptr(0); capability <= unix.CAP_LAST_CAP; capability++ {
		if !keep[capability] {
			drops = append(drops, capability)
		}
	}
	return drops
}
