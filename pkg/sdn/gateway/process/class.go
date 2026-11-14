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
	"slices"

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
	// AddressFamilies are the socket(2) families the process may open. The
	// seccomp filter fails a socket or socketpair in any other family with
	// EAFNOSUPPORT, so an empty list refuses every socket.
	AddressFamilies []uint32
	// MemoryMax is the cgroup v2 memory.max in bytes; 0 leaves it unset.
	MemoryMax int64
	// CPUMax is the cgroup v2 cpu.max value ("200000 100000" is two cores);
	// empty leaves it unset.
	CPUMax string
	// Unprivileged reports whether the child drops to the configured
	// service uid. Kernel-programming processes stay root with a bounding
	// set of Capabilities; parsers do not stay root at all.
	Unprivileged bool
	// Supervised reports whether the process has moved out of gatewayd serve
	// into a supervised child. The processes move one at a time; until one
	// does, its services keep running inside the supervisor's own process.
	Supervised bool
	// ReconcilesDesired reports whether the process applies a section of
	// the desired document. The supervisor sends the document to each such
	// child on every apply and gives it to the child at every launch.
	ReconcilesDesired bool
	// StateDir is the directory under the gatewayd data directory
	// (--data-dir) the process writes its own state to. The supervisor
	// creates it before every launch, owned by the credentials the process
	// runs with, so an unprivileged child can write there. Empty means the
	// process keeps no state of its own.
	StateDir string
	// StateFiles are the files in StateDir the process reads back. A
	// gatewayd that ran the process's services unsupervised, as root, left
	// them root-owned; the supervisor hands each that exists to the
	// process's credentials before every launch, keeping its content.
	StateFiles []string
}

// serviceFamilies are the address families every gateway process opens:
// AF_UNIX for the supervisor and datapath IPC, AF_INET and AF_INET6 for its
// listeners and peers, and AF_NETLINK, over which the datapath programs
// nftables, routes, XFRM and WireGuard and every process's net package reads
// interfaces and addresses (NETLINK_ROUTE). No parser process opens
// AF_PACKET; only the datapath does, see datapathFamilies.
var serviceFamilies = []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}

// datapathFamilies are serviceFamilies plus AF_PACKET: the FHRP speaker
// runs in the datapath and its announcer sends the IPv4 takeover's
// gratuitous ARP over an AF_PACKET socket (CAP_NET_RAW is already kept).
var datapathFamilies = append(slices.Clone(serviceFamilies), unix.AF_PACKET)

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
			gateway.ServiceFHRP,
			gateway.ServiceOverlay,
		},
		Capabilities:    []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW},
		AddressFamilies: datapathFamilies,
		MemoryMax:       512 << 20,
		CPUMax:          "200000 100000",
		// Last to move: the one supervised process that is not unprivileged.
		// It keeps exactly the two capabilities the kernel needs from it,
		// holds the OVS runtime, and is reached by parser children only
		// through the datapath IPC service.
		Supervised: true,
		// The load-balancer and NAT sections.
		ReconcilesDesired: true,
	},
	{
		Name:            "routing",
		Class:           ClassParser,
		Services:        []string{gateway.ServiceTransit},
		Capabilities:    []uintptr{unix.CAP_NET_BIND_SERVICE},
		AddressFamilies: serviceFamilies,
		MemoryMax:       512 << 20,
		CPUMax:          "100000 100000",
		Unprivileged:    true,
		// First to move: the smallest privilege set of the processes that
		// have a backend (one capability, no kernel programming), and BGP
		// is the most exposed untrusted parser gatewayd runs.
		Supervised: true,
	},
	{
		Name:            "proxy",
		Class:           ClassParser,
		Services:        []string{gateway.ServiceProxy},
		Capabilities:    []uintptr{unix.CAP_NET_BIND_SERVICE},
		AddressFamilies: serviceFamilies,
		MemoryMax:       1 << 30,
		CPUMax:          "200000 100000",
		Unprivileged:    true,
		// Second to move: the same one capability, and the next most
		// exposed parser — it terminates TLS from the internet.
		Supervised: true,
	},
	{
		Name:            "provisioning",
		Class:           ClassParser,
		Services:        []string{gateway.ServiceDHCP, gateway.ServicePXE, gateway.ServiceEdge},
		Capabilities:    []uintptr{unix.CAP_NET_BIND_SERVICE},
		AddressFamilies: serviceFamilies,
		MemoryMax:       256 << 20,
		CPUMax:          "100000 100000",
		Unprivileged:    true,
		// Third to move: one capability, for the privileged ports it
		// answers on (DHCP 67, TFTP 69, PXE over HTTP 80), and every
		// request it parses comes from a device not yet trusted.
		Supervised: true,
	},
	{
		Name:            "vpn",
		Class:           ClassParser,
		Services:        []string{gateway.ServiceManagementVPN},
		AddressFamilies: []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6},
		MemoryMax:       256 << 20,
		CPUMax:          "100000 100000",
		Unprivileged:    true,
		// Fourth to move, and with the least: no capability at all. Its
		// data plane is reached through the datapath IPC service, which
		// keeps CAP_NET_ADMIN, and its admission listener's default port
		// (4433) is unprivileged. AF_UNIX for that IPC, AF_INET and
		// AF_INET6 for the listener and the control plane; it reads no
		// routes or links, so no AF_NETLINK.
		Supervised: true,
		// The vpn section.
		ReconcilesDesired: true,
		// Its revocation journal, vpn/pending-revocations.json.
		StateDir:   "vpn",
		StateFiles: []string{gateway.VPNRevocationJournalFile},
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
