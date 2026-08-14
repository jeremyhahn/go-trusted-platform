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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// OpenFlow protocol constants. Values match the OVS match string syntax used
// by ovs-ofctl.
const (
	etherTypeARP  = uint16(0x0806)
	etherTypeIPv4 = uint16(0x0800)

	ipProtoTCP  = uint8(6)
	ipProtoUDP  = uint8(17)
	ipProtoICMP = uint8(1)

	portDHCPClient = uint16(68)
	portDHCPServer = uint16(67)
	portDNS        = uint16(53)
	portDNSAlt1    = uint16(8053)
	portDNSAlt2    = uint16(9053)
	portTFTP       = uint16(69)
	portHTTP       = uint16(80)
	portHTTPS      = uint16(443)
	portHTTPSAlt1  = uint16(8443)
	portHTTPSAlt2  = uint16(9443)

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
	prioTrustedEW    = 100            // trusted east-west (per doc: priority=100)
	prioPublicDeny   = 200            // public→trusted drop (per doc: priority=200)
	prioPublicEW     = 100            // public east-west
	prioStorageEW    = 100            // storage east-west
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
// The built-in generators (quarantine, provisioning, trusted, public, storage,
// management) are pre-registered. User-defined zones that do not match any
// built-in name receive generic matrix-driven rules only (nil generator entry).
func NewGeneratorSet(cfg ZoneFlowConfig) *GeneratorSet {
	gs := &GeneratorSet{
		cfg:        cfg,
		generators: make(map[zone.Zone]generator, 8),
	}
	gs.generators[zone.ZoneQuarantine] = gs.quarantine
	gs.generators[zone.ZoneProvisioning] = gs.provisioning
	gs.generators[zone.ZoneTrusted] = gs.trusted
	gs.generators[zone.ZonePublic] = gs.public
	gs.generators[zone.ZoneStorage] = gs.storage
	gs.generators[zone.ZoneManagement] = gs.management
	return gs
}

// Generate returns the complete set of OpenFlow rules for portID in zone z
// with the given VLAN ID. When z maps to a built-in generator its template
// rules are returned; user-defined zones without a built-in template return
// an empty slice (only matrix rules apply at that point, emitted separately by
// CompileMatrixRules).
func (gs *GeneratorSet) Generate(portID string, z zone.Zone, vlanID uint16) []FlowRule {
	gen, ok := gs.generators[z]
	if !ok || gen == nil {
		return nil
	}
	return gen(portID, vlanID)
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
func CompileMatrixRules(cfg MatrixRuleConfig) []FlowRule {
	var flows []FlowRule

	for _, from := range cfg.Zones {
		fromNet, ok := cfg.NetworksByZone[from.Name]
		if !ok || fromNet.VLAN == 0 {
			continue
		}

		for _, to := range cfg.Zones {
			if from.Name == to.Name {
				continue // intra-zone handled by per-zone template
			}

			toNet, ok := cfg.NetworksByZone[to.Name]
			if !ok || toNet.Subnet == "" {
				continue
			}

			verdict := cfg.Matrix.Allowed(from.Name, to.Name)

			if !verdict.Allowed {
				// Emit a deny rule for this (from→to) pair.
				flows = append(flows, FlowRule{
					Table:    0,
					Priority: prioMatrixDeny,
					Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_dst=%s", fromNet.VLAN, toNet.Subnet),
					Actions:  "drop",
				})
				continue
			}

			// Allowed pair with a service scope: emit per-service permit rules.
			// Pairs without a service scope (nil/empty Services) need no
			// additional matrix rule — the template's normal action covers them.
			if len(verdict.Services) > 0 {
				for _, svc := range verdict.Services {
					flows = append(flows, serviceFlowRules(fromNet.VLAN, toNet.Subnet, svc, prioMatrixAllow)...)
				}
			}
		}
	}

	return flows
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
	prioCTGateIP   = 100 // per-zone ip → ct() gate flows
	prioCTGateMiss = 1   // non-IP / unclassified traffic bypasses conntrack
	prioCTInvalid  = 400 // drop invalid tracked connections
	prioCTEstRel   = 300 // fast-path established/related connections
	prioCTMiss     = 0   // verdict-table miss (DefaultPolicy)
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
//	                    non-IP traffic skips conntrack (goto table 30).
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
func CompileStatefulMatrixRules(cfg MatrixRuleConfig, ctZones map[zone.Zone]uint16) []FlowRule {
	var flows []FlowRule

	// Table 20 base: non-IP and unclassified traffic bypasses conntrack.
	flows = append(flows, FlowRule{
		Table:    tableCTGate,
		Priority: prioCTGateMiss,
		Actions:  fmt.Sprintf("goto_table:%d", tableAfterCT),
	})

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

		// Gate: send this zone's IP traffic through its conntrack zone.
		flows = append(flows, FlowRule{
			Table:    tableCTGate,
			Priority: prioCTGateIP,
			Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800", fromNet.VLAN),
			Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", tableCTVerdict, ctZone),
		})

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

		// Matrix verdicts for new connections from this zone.
		for _, to := range cfg.Zones {
			toNet, ok := cfg.NetworksByZone[to.Name]
			if !ok || toNet.Subnet == "" {
				continue
			}

			match := fmt.Sprintf("ct_state=+new+trk,dl_vlan=%d,dl_type=0x0800,nw_dst=%s",
				fromNet.VLAN, toNet.Subnet)

			if cfg.Matrix.Allowed(from.Name, to.Name).Allowed {
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
// OpenFlow rules. Named services that do not have a port-level representation
// in the current rule vocabulary (e.g. "auth", "remediation") are handled by
// the per-zone templates and return no additional matrix rules here.
func serviceFlowRules(fromVLAN uint16, toSubnet, service string, priority int) []FlowRule {
	var flows []FlowRule

	switch service {
	case "dhcp":
		flows = append(flows,
			FlowRule{
				Table:    0,
				Priority: priority,
				Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_proto=17,tp_src=%d,tp_dst=%d", fromVLAN, portDHCPClient, portDHCPServer),
				Actions:  "normal",
			},
		)
	case "dns":
		for _, p := range []uint16{portDNS, portDNSAlt1, portDNSAlt2} {
			flows = append(flows,
				FlowRule{
					Table:    0,
					Priority: priority,
					Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_proto=17,nw_dst=%s,tp_dst=%d", fromVLAN, toSubnet, p),
					Actions:  "normal",
				},
				FlowRule{
					Table:    0,
					Priority: priority,
					Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", fromVLAN, toSubnet, p),
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
					Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", fromVLAN, toSubnet, p),
					Actions:  "normal",
				},
			)
		}
	case "tftp":
		flows = append(flows,
			FlowRule{
				Table:    0,
				Priority: priority,
				Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_proto=17,tp_dst=%d", fromVLAN, portTFTP),
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
func (gs *GeneratorSet) quarantine(portID string, vlanID uint16) []FlowRule {
	var flows []FlowRule

	// ARP
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioARP,
		Match:    matchInVLAN(portID, vlanID, "dl_type=0x0806"),
		Actions:  "normal",
	})

	// DHCP client→server
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioDHCP,
		Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,tp_src=%d,tp_dst=%d", portDHCPClient, portDHCPServer)),
		Actions:  "normal",
	})

	// DNS (to configured server, or broadcast)
	cfg := gs.cfg.Quarantine
	if cfg.DNSServerIP != nil {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioDNS,
			Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,nw_dst=%s,tp_dst=%d", cfg.DNSServerIP, portDNS)),
			Actions:  "normal",
		})
	} else {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioDNS,
			Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,tp_dst=%d", portDNS)),
			Actions:  "normal",
		})
	}

	// Remediation servers (auth + remediation): HTTPS only by default
	remPorts := cfg.AllowedPorts
	if len(remPorts) == 0 {
		remPorts = []uint16{portHTTPS}
	}
	for _, ip := range cfg.RemediationServerIPs {
		for _, p := range remPorts {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioRemediation,
				Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", ip, p)),
				Actions:  "normal",
			})
		}
	}

	// Scanning servers
	for _, ip := range cfg.ScanningServerIPs {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioScanning,
			Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_dst=%s", ip)),
			Actions:  "normal",
		})
	}

	// Notification portal (HTTP + HTTPS)
	if cfg.NotificationServerIP != nil {
		for _, p := range []uint16{portHTTP, portHTTPS} {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioNotification,
				Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", cfg.NotificationServerIP, p)),
				Actions:  "normal",
			})
		}
	}

	// Default drop (lowest priority for quarantine)
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioQDropDefault,
		Match:    matchInVLAN(portID, vlanID, ""),
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
func (gs *GeneratorSet) provisioning(portID string, vlanID uint16) []FlowRule {
	var flows []FlowRule

	// ARP
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioARP,
		Match:    matchInVLAN(portID, vlanID, "dl_type=0x0806"),
		Actions:  "normal",
	})

	// DHCP
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioDHCP,
		Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,tp_src=%d,tp_dst=%d", portDHCPClient, portDHCPServer)),
		Actions:  "normal",
	})

	// DNS
	cfg := gs.cfg.Provisioning
	dnsPorts := []uint16{portDNS, portDNSAlt1, portDNSAlt2}
	if len(cfg.DNSServerIPs) == 0 {
		for _, p := range dnsPorts {
			flows = append(flows,
				FlowRule{
					Table:    0,
					Priority: prioDNS,
					Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,tp_dst=%d", p)),
					Actions:  "normal",
				},
			)
		}
	} else {
		for _, ip := range cfg.DNSServerIPs {
			for _, p := range dnsPorts {
				flows = append(flows, FlowRule{
					Table:    0,
					Priority: prioDNS,
					Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,nw_dst=%s,tp_dst=%d", ip, p)),
					Actions:  "normal",
				})
			}
		}
	}

	// TFTP (PXE boot)
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioTFTP,
		Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=17,tp_dst=%d", portTFTP)),
		Actions:  "normal",
	})

	// ACME / HTTPS
	acmePorts := []uint16{portHTTPS, portHTTPSAlt1, portHTTPSAlt2}
	if len(cfg.ACMEServerIPs) == 0 {
		for _, p := range acmePorts {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioACME,
				Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,tp_dst=%d", p)),
				Actions:  "normal",
			})
		}
	} else {
		for _, ip := range cfg.ACMEServerIPs {
			for _, p := range acmePorts {
				flows = append(flows, FlowRule{
					Table:    0,
					Priority: prioACME,
					Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", ip, p)),
					Actions:  "normal",
				})
			}
		}
	}

	// Package repos (HTTP + HTTPS)
	repoPorts := []uint16{portHTTP, portHTTPS}
	if len(cfg.PackageRepoIPs) == 0 {
		for _, p := range repoPorts {
			flows = append(flows, FlowRule{
				Table:    0,
				Priority: prioPackageRepo,
				Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,tp_dst=%d", p)),
				Actions:  "normal",
			})
		}
	} else {
		for _, ip := range cfg.PackageRepoIPs {
			for _, p := range repoPorts {
				flows = append(flows, FlowRule{
					Table:    0,
					Priority: prioPackageRepo,
					Match:    matchInVLAN(portID, vlanID, fmt.Sprintf("dl_type=0x0800,nw_proto=6,nw_dst=%s,tp_dst=%d", ip, p)),
					Actions:  "normal",
				})
			}
		}
	}

	// ICMP if configured
	if cfg.AllowICMP {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioPackageRepo - 50,
			Match:    matchInVLAN(portID, vlanID, "dl_type=0x0800,nw_proto=1"),
			Actions:  "normal",
		})
	}

	// Default drop
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioDefaultDrop,
		Match:    matchInVLAN(portID, vlanID, ""),
		Actions:  "drop",
	})

	return flows
}

// trusted implements the trusted zone flow template.
//
// Rule set (from docs/architecture/reference-network.md):
//
//	priority=100  in_port=<port>,dl_vlan=<trusted>,actions=normal
//
// East-west per-profile ACLs are layered on top by the engine's
// GenerateAuthorizationRules; the template installs the base allow rule.
func (gs *GeneratorSet) trusted(portID string, vlanID uint16) []FlowRule {
	return []FlowRule{
		{
			Table:    0,
			Priority: prioTrustedEW,
			Match:    matchInVLAN(portID, vlanID, ""),
			Actions:  "normal",
		},
	}
}

// public implements the public zone flow template.
//
// Rule set (from docs/architecture/reference-network.md):
//
//	priority=200  dl_vlan=<public>,ip,nw_dst=<trusted_subnet>,actions=drop
//	priority=100  in_port=<port>,dl_vlan=<public>,actions=normal
func (gs *GeneratorSet) public(portID string, vlanID uint16) []FlowRule {
	var flows []FlowRule

	// Drop public→trusted (defense-in-depth)
	if gs.cfg.Public.TrustedSubnet != "" {
		flows = append(flows, FlowRule{
			Table:    0,
			Priority: prioPublicDeny,
			Match:    fmt.Sprintf("dl_vlan=%d,dl_type=0x0800,nw_dst=%s", vlanID, gs.cfg.Public.TrustedSubnet),
			Actions:  "drop",
		})
	}

	// Public ingress/egress
	flows = append(flows, FlowRule{
		Table:    0,
		Priority: prioPublicEW,
		Match:    matchInVLAN(portID, vlanID, ""),
		Actions:  "normal",
	})

	return flows
}

// storage implements the storage zone flow template.
//
// Storage is isolated; only storage↔trusted and storage intra-zone are allowed.
// The matrix handles the inter-zone direction; the template provides the
// intra-zone east-west allow rule.
func (gs *GeneratorSet) storage(portID string, vlanID uint16) []FlowRule {
	return []FlowRule{
		{
			Table:    0,
			Priority: prioStorageEW,
			Match:    matchInVLAN(portID, vlanID, ""),
			Actions:  "normal",
		},
	}
}

// management implements the management zone flow template.
//
// Management is OOB and must never route to any data zone. The template
// allows intra-zone traffic (BMC-to-BMC management) and drops everything else.
func (gs *GeneratorSet) management(portID string, vlanID uint16) []FlowRule {
	return []FlowRule{
		{
			Table:    0,
			Priority: 100,
			Match:    matchInVLAN(portID, vlanID, ""),
			Actions:  "normal",
		},
	}
}

// --------------------------------------------------------------------------
// Match string helpers
// --------------------------------------------------------------------------

// matchInVLAN builds an OpenFlow match string scoped to portID and vlanID.
// When extra is non-empty it is appended, comma-separated.
func matchInVLAN(portID string, vlanID uint16, extra string) string {
	parts := []string{
		fmt.Sprintf("in_port=%s", portID),
		fmt.Sprintf("dl_vlan=%d", vlanID),
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, ",")
}
