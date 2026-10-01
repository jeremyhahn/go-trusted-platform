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

package zoneflows

import (
	"fmt"
	"net"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// OpenFlow protocol constants. Values match the OVS match string syntax used
// by ovs-ofctl.
const (
	portDHCPClient = uint16(68)
	portDHCPServer = uint16(67)
	// DHCPv6 (RFC 8415) client and server ports.
	portDHCP6Client = uint16(546)
	portDHCP6Server = uint16(547)
	portDNS         = uint16(53)
	portDNSAlt1     = uint16(8053)
	portDNSAlt2     = uint16(9053)
	portTFTP        = uint16(69)
	portHTTP        = uint16(80)
	portHTTPS       = uint16(443)
	portHTTPSAlt1   = uint16(8443)
	portHTTPSAlt2   = uint16(9443)

	// Priority offsets relative to basePriority (1000). Chosen to mirror the
	// per-zone rule sets in docs/architecture/reference-network.md.
	prioBase         = 1000
	prioARP          = prioBase + 900 // 1900
	prioDHCP         = prioBase + 850 // 1850
	prioDNS          = prioBase + 800 // 1800
	prioTFTP         = prioBase + 750 // 1750
	prioACME         = prioBase + 700 // 1700 — provisioning: ACME/HTTPS
	prioPackageRepo  = prioBase + 650 // 1650 — provisioning: package repos
	prioScanning     = prioBase + 700 // 1700 — quarantine: scanning servers
	prioRemediation  = prioBase + 650 // 1650 — quarantine: remediation servers
	prioNotification = prioBase + 600 // 1600 — quarantine: notification portal
	prioEastWest     = 100            // intra-zone east-west (per doc: priority=100)
	prioMatrixDeny   = 200            // inter-zone deny flows
	prioMatrixAllow  = 100            // inter-zone allow flows
	prioDefaultDrop  = prioBase - 100 // 900 — provisioning default drop
	prioQDropDefault = prioBase + 100 // 1100 — quarantine default drop (per doc: priority=100 relative to base)
)

// GeneratorSet holds per-zone generators selected by map dispatch.
type GeneratorSet struct {
	cfg        ZoneFlowConfig
	generators map[zone.Zone]generator
}

// NewGeneratorSet constructs a GeneratorSet from the supplied ZoneFlowConfig.
// The lifecycle templates (quarantine, provisioning) and the OOB management
// template are pre-registered, and so is the east-west template for every
// built-in zone whose reference policy opens traffic inside the zone
// (fabric, hypervisor, control-plane, storage, backup). Transit and
// owner-defined zones receive generic matrix-driven rules only.
func NewGeneratorSet(cfg ZoneFlowConfig) *GeneratorSet {
	gs := &GeneratorSet{
		cfg:        cfg,
		generators: make(map[zone.Zone]generator, 8),
	}
	gs.generators[zone.ZoneQuarantine] = gs.quarantine
	gs.generators[zone.ZoneProvisioning] = gs.provisioning
	gs.generators[zone.ZoneManagement] = gs.management
	for _, z := range eastWestZones {
		gs.generators[z] = gs.eastWest
	}
	return gs
}

// eastWestZones are the built-in zones whose reference policy opens traffic
// between members of the zone: VTEPs on fabric, live migration on
// hypervisor, Raft and the CP APIs on control-plane, storage clients and
// targets, backup streams.
var eastWestZones = []zone.Zone{
	zone.ZoneFabric,
	zone.ZoneHypervisor,
	zone.ZoneControlPlane,
	zone.ZoneStorage,
	zone.ZoneBackup,
}

// Generate returns the complete set of OpenFlow rules for portID in zone z
// with the given VLAN ID. When z maps to a built-in generator its template
// rules are returned; user-defined zones without a built-in template return
// an empty slice (only matrix rules apply at that point, emitted separately by
// CompileMatrixRules).
func (gs *GeneratorSet) Generate(portID string, z zone.Zone, in Ingress) []FlowRule {
	gen, ok := gs.generators[z]
	if !ok || gen == nil {
		return nil
	}
	return ApplyTerminal(gen(portID, in), gs.cfg.Terminal)
}

// CompileMatrixRules derives inter-zone allow/deny OpenFlow rules from the
// compiled zone.Matrix and the network summaries in cfg. The emitted rules
// implement the default-deny inter-zone posture documented in the reference
// architecture:
//
//   - For each denied (from, to) pair where both zones have a known VLAN and
//     subnet: emit a priority=200 drop rule matching dl_vlan=<from_vlan>
//     ip,nw_dst=<to_subnet>.
//   - For each allowed (from, to) pair with a service allowlist: emit
//     priority=100 allow rules scoped to the declared service ports where the
//     existing rule vocabulary supports it.
//   - Allowed pairs with an empty service list (all services allowed) are
//     covered by the per-zone template's catch-all normal rule and do not need
//     a separate matrix rule.
//
// The management zone is OOB and never appears as a matrix destination here —
// its isolation is enforced by the management template (no routes to data zones).
//
// These rules match tagged ingress only (dl_vlan): traffic arriving on a
// trunk's tagged zones. Traffic that reaches the flow tables untagged, from
// an access port or on a trunk's native VLAN, needs the per-port variant,
// CompileMatrixRulesForPort.
func CompileMatrixRules(cfg MatrixRuleConfig) []FlowRule {
	return compileMatrix(cfg, "", func(n NetworkSummary) string {
		return Tagged(n.VLAN).Match()
	})
}

// CompileMatrixRulesForPort derives the inter-zone rules of one source zone
// for traffic that reaches the flow tables untagged on portID: an access
// port's zone, or a trunk's native zone.
//
// CompileMatrixRules keys every rule on dl_vlan=<source VLAN>, which only
// matches frames that arrive 802.1Q-tagged (a trunk's tagged zones). OVS
// applies a port's tag and native VLAN only in the NORMAL action, so the
// flow tables see an access port's frames, and a trunk's native-VLAN frames,
// without a VLAN header (see Ingress). Those frames are identified by their
// ingress port instead: the same verdicts, keyed on
// in_port=<port>,vlan_tci=0x0000/0x1fff. The rules carry in_port, so the
// per-port flow cleanup removes them with the port's template rules.
func CompileMatrixRulesForPort(cfg MatrixRuleConfig, portID string, from zone.Zone) []FlowRule {
	if portID == "" || from == "" {
		return nil
	}
	return compileMatrix(cfg, from, func(NetworkSummary) string {
		return fmt.Sprintf("in_port=%s,%s", portID, untaggedMatch)
	})
}

// compileMatrix emits the matrix rules of every source zone (or only of
// onlyFrom when it is set), each keyed on the ingress match ingress returns
// for the source zone's network.
func compileMatrix(cfg MatrixRuleConfig, onlyFrom zone.Zone, ingress func(NetworkSummary) string) []FlowRule {
	var flows []FlowRule

	for _, from := range cfg.Zones {
		if onlyFrom != "" && from.Name != onlyFrom {
			continue
		}
		fromNet, ok := cfg.NetworksByZone[from.Name]
		if !ok || fromNet.VLAN == 0 {
			continue
		}
		in := ingress(fromNet)

		for _, to := range cfg.Zones {
			if from.Name == to.Name {
				continue // intra-zone handled by per-zone template
			}

			toNet, ok := cfg.NetworksByZone[to.Name]
			if !ok {
				continue
			}

			verdict := cfg.Matrix.Allowed(from.Name, to.Name)

			// One rule per address family the destination network has a
			// prefix for (#554).
			for _, f := range families {
				toSubnet, ok := toNet.subnetFor(f)
				if !ok {
					continue
				}

				if !verdict.Allowed {
					// Emit a deny rule for this (from→to) pair.
					flows = append(flows, FlowRule{
						Table:    0,
						Priority: prioMatrixDeny,
						Match:    fmt.Sprintf("%s,%s", in, f.ipMatch(f.toDst(toSubnet))),
						Actions:  "drop",
					})
					continue
				}

				// Allowed pair with a service scope: emit per-service permit
				// rules. Pairs without a service scope (nil/empty Services)
				// need no additional matrix rule — the template's normal
				// action covers them.
				for _, svc := range verdict.Services {
					flows = append(flows, serviceFlowRules(f, in, toSubnet, svc, prioMatrixAllow)...)
				}
			}
		}
	}

	return ApplyTerminal(flows, cfg.Terminal)
}

// Conntrack pipeline table numbers. These mirror the overlay pipeline
// tables declared in pkg/sdn/gateway/modes (TableCTGate, TableCTVerdict,
// TableMACLearning); they are re-declared here because zoneflows sits below
// the gateway layer and must not import it.
const (
	tableCTGate    = 20 // conntrack gate: send IP traffic through ct()
	tableCTVerdict = 21 // conntrack verdict: allow/deny per ct_state + matrix
	tableAfterCT   = 30 // continue the overlay pipeline (MAC learning)
)

// Conntrack pipeline priorities for table 20 (gate) and table 21 (verdict).
const (
	prioCTGateIP  = 100 // per-zone ip → ct() gate flows
	prioCTGateND  = 200 // ICMPv6 neighbor discovery bypasses conntrack
	prioCTInvalid = 400 // drop invalid tracked connections
	prioCTEstRel  = 300 // fast-path established/related connections
	prioCTMiss    = 0   // verdict-table miss (DefaultPolicy)
)

// DefaultPolicyAllow is the MatrixRuleConfig.DefaultPolicy value that makes
// the conntrack verdict table-miss continue the pipeline instead of dropping.
const DefaultPolicyAllow = "allow"

// CompileStatefulMatrixRules derives the conntrack-based stateful firewall
// rule set from the compiled zone.Matrix. It emits rules for the ct
// pipeline installed by the gateway firewall service:
//
//	table 20 (gate):    per-zone "ip in VLAN" flows send traffic through
//	                    ct(table=21, zone=<ct zone of the source zone>);
//	                    non-IP traffic skips conntrack through the gateway
//	                    pipeline's table-20 miss (goto table 30).
//	table 21 (verdict): established/related tracked connections fast-path to
//	                    table 30; invalid connections drop; new connections
//	                    consult the inter-zone matrix — allowed pairs commit
//	                    the connection and continue, denied pairs drop. The
//	                    table miss applies cfg.DefaultPolicy.
//
// ctZones maps each zone name to its allocated conntrack zone ID; zones
// without an entry (or without a VLAN-backed network) are skipped, leaving
// their traffic on the non-IP bypass path. Unlike CompileMatrixRules,
// intra-zone (from == to) pairs are emitted too: once traffic is gated
// through conntrack, intra-zone connections also need a commit verdict.
//
// The rules key on dl_vlan, i.e. on tagged ingress. That is correct for the
// gateway datapath this pipeline runs on: the gateway port class is a trunk
// with no native VLAN, so every zone's traffic from the switch arrives
// tagged. Untagged ingress (an access port's zone, a native VLAN) is not
// classified here and takes the non-IP bypass of table 20.
func CompileStatefulMatrixRules(cfg MatrixRuleConfig, ctZones map[zone.Zone]uint16) []FlowRule {
	// Non-IP and unclassified traffic bypasses conntrack through the
	// gateway pipeline's table-20 miss (goto table 30). It is not emitted
	// here: every gateway service gates into table 20, so the miss belongs
	// to the pipeline that all of them share (#614).
	var flows []FlowRule

	// Per source zone: ct gate + tracked-state scaffolding.
	for _, from := range cfg.Zones {
		fromNet, ok := cfg.NetworksByZone[from.Name]
		if !ok || fromNet.VLAN == 0 {
			continue
		}
		ctZone, ok := ctZones[from.Name]
		if !ok {
			continue
		}

		// Gate: send this zone's IP traffic, both families, through its
		// conntrack zone. Neighbor discovery is not gated: ND has no
		// connection to track and a segment cannot resolve its gateway
		// without it.
		for _, f := range families {
			flows = append(flows, FlowRule{
				Table:    tableCTGate,
				Priority: prioCTGateIP,
				Match:    fmt.Sprintf("dl_vlan=%d,%s", fromNet.VLAN, f.dlType),
				Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", tableCTVerdict, ctZone),
			})
		}
		for _, t := range icmpv6NDTypes {
			flows = append(flows, FlowRule{
				Table:    tableCTGate,
				Priority: prioCTGateND,
				Match:    fmt.Sprintf("dl_vlan=%d,%s", fromNet.VLAN, ipv6.ipMatch(fmt.Sprintf("nw_proto=%d,icmp_type=%d", ipv6.icmpProto, t))),
				Actions:  fmt.Sprintf("goto_table:%d", tableAfterCT),
			})
		}

		// Verdict scaffolding: invalid drops, established/related fast-path.
		flows = append(flows,
			FlowRule{
				Table:    tableCTVerdict,
				Priority: prioCTInvalid,
				Match:    fmt.Sprintf("ct_state=+inv+trk,dl_vlan=%d", fromNet.VLAN),
				Actions:  "drop",
			},
			FlowRule{
				Table:    tableCTVerdict,
				Priority: prioCTEstRel,
				Match:    fmt.Sprintf("ct_state=+est+trk,dl_vlan=%d", fromNet.VLAN),
				Actions:  fmt.Sprintf("goto_table:%d", tableAfterCT),
			},
			FlowRule{
				Table:    tableCTVerdict,
				Priority: prioCTEstRel,
				Match:    fmt.Sprintf("ct_state=+rel+trk,dl_vlan=%d", fromNet.VLAN),
				Actions:  fmt.Sprintf("goto_table:%d", tableAfterCT),
			},
		)

		// Matrix verdicts for new connections from this zone, one per
		// address family the destination network has a prefix for.
		for _, to := range cfg.Zones {
			toNet, ok := cfg.NetworksByZone[to.Name]
			if !ok {
				continue
			}
			allowed := cfg.Matrix.Allowed(from.Name, to.Name).Allowed

			for _, f := range families {
				toSubnet, ok := toNet.subnetFor(f)
				if !ok {
					continue
				}
				match := fmt.Sprintf("ct_state=+new+trk,dl_vlan=%d,%s",
					fromNet.VLAN, f.ipMatch(f.toDst(toSubnet)))

				if allowed {
					flows = append(flows, FlowRule{
						Table:    tableCTVerdict,
						Priority: prioMatrixAllow,
						Match:    match,
						Actions:  fmt.Sprintf("ct(commit,zone=%d),goto_table:%d", ctZone, tableAfterCT),
					})
					continue
				}

				flows = append(flows, FlowRule{
					Table:    tableCTVerdict,
					Priority: prioMatrixDeny,
					Match:    match,
					Actions:  "drop",
				})
			}
		}
	}

	// Verdict table miss: DefaultPolicy.
	missActions := "drop"
	if cfg.DefaultPolicy == DefaultPolicyAllow {
		missActions = fmt.Sprintf("goto_table:%d", tableAfterCT)
	}
	flows = append(flows, FlowRule{
		Table:    tableCTVerdict,
		Priority: prioCTMiss,
		Actions:  missActions,
	})

	return flows
}

// serviceFlowRules maps service names from the zone.ZonePath vocabulary to
// OpenFlow rules for one address family. Named services that do not have a
// port-level representation in the current rule vocabulary (e.g. "auth",
// "remediation") are handled by the per-zone templates and return no
// additional matrix rules here.
func serviceFlowRules(f family, ingress string, toSubnet, service string, priority int) []FlowRule {
	var flows []FlowRule

	switch service {
	case "dhcp":
		flows = append(flows,
			FlowRule{
				Table:    0,
				Priority: priority,
				Match:    fmt.Sprintf("%s,%s", ingress, f.dhcpMatch()),
				Actions:  "normal",
			},
		)
	case "dns":
		for _, p := range []uint16{portDNS, portDNSAlt1, portDNSAlt2} {
			flows = append(flows,
				FlowRule{
					Table:    0,
					Priority: priority,
					Match:    fmt.Sprintf("%s,%s", ingress, f.ipMatch("nw_proto=17", f.toDst(toSubnet), fmt.Sprintf("tp_dst=%d", p))),
					Actions:  "normal",
				},
				FlowRule{
					Table:    0,
					Priority: priority,
					Match:    fmt.Sprintf("%s,%s", ingress, f.ipMatch("nw_proto=6", f.toDst(toSubnet), fmt.Sprintf("tp_dst=%d", p))),
					Actions:  "normal",
				},
			)
		}
	case "acme":
		for _, p := range []uint16{portHTTPS, portHTTPSAlt1, portHTTPSAlt2} {
			flows = append(flows,
				FlowRule{
					Table:    0,
					Priority: priority,
					Match:    fmt.Sprintf("%s,%s", ingress, f.ipMatch("nw_proto=6", f.toDst(toSubnet), fmt.Sprintf("tp_dst=%d", p))),
					Actions:  "normal",
				},
			)
		}
	case "tftp":
		flows = append(flows,
			FlowRule{
				Table:    0,
				Priority: priority,
				Match:    fmt.Sprintf("%s,%s", ingress, f.ipMatch("nw_proto=17", fmt.Sprintf("tp_dst=%d", portTFTP))),
				Actions:  "normal",
			},
		)
	default:
		// auth, remediation, storage-protocols: handled by per-zone templates.
	}

	return flows
}

// --------------------------------------------------------------------------
// Per-zone template generators (keyed by zone.Zone via map dispatch)
// --------------------------------------------------------------------------

// quarantine implements the quarantine zone flow template.
//
// Rule set (from docs/architecture/reference-network.md):
//
//	ARP             priority=1900
//	DHCP            priority=1850
//	DNS to dns_ip   priority=1800
//	auth/remediation HTTPS to remediation_ip  priority=1700/1650
//	default drop    priority=1100
func (gs *GeneratorSet) quarantine(portID string, in Ingress) []FlowRule {
	var flows []FlowRule

	// ARP, and its IPv6 counterpart: neighbor discovery.
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioARP,
		Match:    matchInVLAN(portID, in, "dl_type=0x0806"),
		Actions:  "normal",
	})
	flows = append(flows, neighborDiscoveryRules(portID, in, prioARP)...)

	// DHCP client→server, both families.
	for _, f := range families {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioDHCP,
			Match:    matchInVLAN(portID, in, f.dhcpMatch()),
			Actions:  "normal",
		})
	}

	// DNS (to configured server, or any server in both families)
	cfg := gs.cfg.Quarantine
	if cfg.DNSServerIP != nil {
		f := familyOf(cfg.DNSServerIP)
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioDNS,
			Match:    matchInVLAN(portID, in, f.ipMatch("nw_proto=17", f.toDst(cfg.DNSServerIP.String()), fmt.Sprintf("tp_dst=%d", portDNS))),
			Actions:  "normal",
		})
	} else {
		for _, f := range families {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioDNS,
				Match:    matchInVLAN(portID, in, f.ipMatch("nw_proto=17", fmt.Sprintf("tp_dst=%d", portDNS))),
				Actions:  "normal",
			})
		}
	}

	// Remediation servers (auth + remediation): HTTPS only by default
	remPorts := cfg.AllowedPorts
	if len(remPorts) == 0 {
		remPorts = []uint16{portHTTPS}
	}
	for _, ip := range cfg.RemediationServerIPs {
		f := familyOf(ip)
		for _, p := range remPorts {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioRemediation,
				Match:    matchInVLAN(portID, in, f.ipMatch("nw_proto=6", f.toDst(ip.String()), fmt.Sprintf("tp_dst=%d", p))),
				Actions:  "normal",
			})
		}
	}

	// Scanning servers
	for _, ip := range cfg.ScanningServerIPs {
		f := familyOf(ip)
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioScanning,
			Match:    matchInVLAN(portID, in, f.ipMatch(f.toDst(ip.String()))),
			Actions:  "normal",
		})
	}

	// Notification portal (HTTP + HTTPS)
	if cfg.NotificationServerIP != nil {
		f := familyOf(cfg.NotificationServerIP)
		for _, p := range []uint16{portHTTP, portHTTPS} {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioNotification,
				Match:    matchInVLAN(portID, in, f.ipMatch("nw_proto=6", f.toDst(cfg.NotificationServerIP.String()), fmt.Sprintf("tp_dst=%d", p))),
				Actions:  "normal",
			})
		}
	}

	// Default drop (lowest priority for quarantine)
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioQDropDefault,
		Match:    matchInVLAN(portID, in, ""),
		Actions:  "drop",
		Cookie:   fmt.Sprintf("quarantine:%s", portID),
	})

	return flows
}

// provisioning implements the provisioning zone flow template.
//
// Rule set (from docs/architecture/reference-network.md):
//
//	ARP           priority=1900
//	DHCP          priority=1850
//	DNS           priority=1800
//	TFTP          priority=1750
//	ACME/HTTPS    priority=1700
//	package repos priority=1650
//	default drop  priority=900
func (gs *GeneratorSet) provisioning(portID string, in Ingress) []FlowRule {
	var flows []FlowRule

	// ARP, and its IPv6 counterpart: neighbor discovery.
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioARP,
		Match:    matchInVLAN(portID, in, "dl_type=0x0806"),
		Actions:  "normal",
	})
	flows = append(flows, neighborDiscoveryRules(portID, in, prioARP)...)

	// DHCP, both families.
	for _, f := range families {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioDHCP,
			Match:    matchInVLAN(portID, in, f.dhcpMatch()),
			Actions:  "normal",
		})
	}

	cfg := gs.cfg.Provisioning

	// DNS
	flows = append(flows, gs.serverRules(portID, in, prioDNS, "nw_proto=17",
		cfg.DNSServerIPs, []uint16{portDNS, portDNSAlt1, portDNSAlt2})...)

	// TFTP (PXE boot), both families.
	for _, f := range families {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioTFTP,
			Match:    matchInVLAN(portID, in, f.ipMatch("nw_proto=17", fmt.Sprintf("tp_dst=%d", portTFTP))),
			Actions:  "normal",
		})
	}

	// ACME / HTTPS
	flows = append(flows, gs.serverRules(portID, in, prioACME, "nw_proto=6",
		cfg.ACMEServerIPs, []uint16{portHTTPS, portHTTPSAlt1, portHTTPSAlt2})...)

	// Package repos (HTTP + HTTPS)
	flows = append(flows, gs.serverRules(portID, in, prioPackageRepo, "nw_proto=6",
		cfg.PackageRepoIPs, []uint16{portHTTP, portHTTPS})...)

	// ICMP if configured: ICMP for IPv4, ICMPv6 for IPv6.
	if cfg.AllowICMP {
		for _, f := range families {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioPackageRepo - 50,
				Match:    matchInVLAN(portID, in, f.ipMatch(fmt.Sprintf("nw_proto=%d", f.icmpProto))),
				Actions:  "normal",
			})
		}
	}

	// Default drop
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioDefaultDrop,
		Match:    matchInVLAN(portID, in, ""),
		Actions:  "drop",
	})

	return flows
}

// serverRules emits the "reach these servers on these ports" allowances a
// provisioning-style template uses. With no server addresses configured the
// ports are open to any destination in both families; with addresses, each
// address gets rules in its own family only.
func (gs *GeneratorSet) serverRules(portID string, in Ingress, priority int, proto string, servers []net.IP, ports []uint16) []FlowRule {
	var flows []FlowRule
	if len(servers) == 0 {
		for _, f := range families {
			for _, p := range ports {
				flows = append(flows, FlowRule{
					Table:    0,
					Priority: priority,
					Match:    matchInVLAN(portID, in, f.ipMatch(proto, fmt.Sprintf("tp_dst=%d", p))),
					Actions:  "normal",
				})
			}
		}
		return flows
	}
	for _, ip := range servers {
		f := familyOf(ip)
		for _, p := range ports {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: priority,
				Match:    matchInVLAN(portID, in, f.ipMatch(proto, f.toDst(ip.String()), fmt.Sprintf("tp_dst=%d", p))),
				Actions:  "normal",
			})
		}
	}
	return flows
}

// eastWest implements the intra-zone template of the zones in
// eastWestZones: members of the zone reach each other. The matrix rules
// compiled by CompileMatrixRules deny the other zones' subnets above it.
//
//	priority=100  in_port=<port>,dl_vlan=<zone>,actions=normal
func (gs *GeneratorSet) eastWest(portID string, in Ingress) []FlowRule {
	return []FlowRule{
		{
			Table:    0,
			Priority: prioEastWest,
			Match:    matchInVLAN(portID, in, ""),
			Actions:  "normal",
		},
	}
}

// management implements the management zone flow template.
//
// Management is OOB (BMCs only) and must never route to any data zone. The
// template forwards on the management VLAN itself; the matrix rules drop
// every other zone's subnet above it.
func (gs *GeneratorSet) management(portID string, in Ingress) []FlowRule {
	return []FlowRule{
		{
			Table:    0,
			Priority: 100,
			Match:    matchInVLAN(portID, in, ""),
			Actions:  "normal",
		},
	}
}

// --------------------------------------------------------------------------
// Match string helpers
// --------------------------------------------------------------------------

// matchInVLAN builds an OpenFlow match string scoped to portID and to the
// way the zone's frames arrive on it (see Ingress). When extra is non-empty
// it is appended, comma-separated.
func matchInVLAN(portID string, in Ingress, extra string) string {
	parts := []string{
		fmt.Sprintf("in_port=%s", portID),
		in.Match(),
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, ",")
}

// --------------------------------------------------------------------------
// Address families
// --------------------------------------------------------------------------

// family names one IP address family in OVS match syntax. Every rule that
// matches on an IP header is compiled once per family (#554): the IPv4
// rule and its IPv6 twin differ only in these fields, so a policy that is
// address-family-neutral cannot be enforced for one family and skipped for
// the other.
type family struct {
	// name is the family's short name, used in test output.
	name string
	// dlType is the EtherType match: dl_type=0x0800 or dl_type=0x86dd.
	dlType string
	// dst is the destination address field: nw_dst or ipv6_dst.
	dst string
	// icmpProto is the IP protocol number carrying the family's ICMP.
	icmpProto uint8
}

var (
	ipv4 = family{name: "ipv4", dlType: "dl_type=0x0800", dst: "nw_dst", icmpProto: 1}
	ipv6 = family{name: "ipv6", dlType: "dl_type=0x86dd", dst: "ipv6_dst", icmpProto: 58}
)

// families is the compile order: IPv4 first, then its IPv6 twin.
var families = []family{ipv4, ipv6}

// familyOf reports the family an address belongs to.
func familyOf(ip net.IP) family {
	if ip.To4() != nil {
		return ipv4
	}
	return ipv6
}

// familyOfPrefix reports the family a CIDR string belongs to; an
// unparseable string is treated as IPv4 so a legacy caller's rule is
// emitted unchanged rather than silently dropped.
func familyOfPrefix(cidr string) family {
	if strings.Contains(cidr, ":") {
		return ipv6
	}
	return ipv4
}

// subnetFor returns the summary's subnet for the family and whether it has
// one.
func (n NetworkSummary) subnetFor(f family) (string, bool) {
	if f.name == ipv6.name {
		return n.Subnet6, n.Subnet6 != ""
	}
	return n.Subnet, n.Subnet != ""
}

// ipMatch renders "dl_type=…" followed by the optional extra match fields.
func (f family) ipMatch(extra ...string) string {
	parts := append([]string{f.dlType}, extra...)
	return strings.Join(parts, ",")
}

// toDst renders the family's destination-address match for cidr.
func (f family) toDst(cidr string) string {
	return f.dst + "=" + cidr
}

// dhcpMatch renders the family's DHCP client→server exchange.
func (f family) dhcpMatch() string {
	if f.name == ipv6.name {
		return f.ipMatch(fmt.Sprintf("nw_proto=17,tp_src=%d,tp_dst=%d", portDHCP6Client, portDHCP6Server))
	}
	return f.ipMatch(fmt.Sprintf("nw_proto=17,tp_src=%d,tp_dst=%d", portDHCPClient, portDHCPServer))
}

// icmpv6NDTypes are the ICMPv6 Neighbor Discovery messages (RFC 4861) an
// IPv6 segment cannot function without: router solicitation and
// advertisement, neighbor solicitation and advertisement, redirect. They
// are permitted wherever ARP is.
var icmpv6NDTypes = []uint8{133, 134, 135, 136, 137}

// neighborDiscoveryRules returns the ICMPv6 ND allowances that pair with an
// ARP allowance on a port.
func neighborDiscoveryRules(portID string, in Ingress, priority int) []FlowRule {
	flows := make([]FlowRule, 0, len(icmpv6NDTypes))
	for _, t := range icmpv6NDTypes {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: priority,
			Match:    matchInVLAN(portID, in, ipv6.ipMatch(fmt.Sprintf("nw_proto=%d,icmp_type=%d", ipv6.icmpProto, t))),
			Actions:  "normal",
		})
	}
	return flows
}
