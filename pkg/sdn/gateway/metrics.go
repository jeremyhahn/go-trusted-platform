// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gateway

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// metricNamespace prefixes every gateway metric.
const metricNamespace = "gatewayd"

// SnapshotSource is what the metrics collector reads. *Gateway implements
// it; a test or a control plane holding cached snapshots can supply another.
type SnapshotSource interface {
	Snapshot() *gwstate.Snapshot
}

// Collector exports the telemetry snapshot as Prometheus metrics (#594).
// It is a pull collector: every scrape takes one fresh snapshot, so the
// metrics and the control plane's telemetry always agree, and there is no
// second copy of the state to keep current.
type Collector struct {
	source SnapshotSource

	serviceActive   *prometheus.Desc
	serviceHealthy  *prometheus.Desc
	peerState       *prometheus.Desc
	peerUptime      *prometheus.Desc
	peerPrefixes    *prometheus.Desc
	bfdSessionUp    *prometheus.Desc
	bfdFailures     *prometheus.Desc
	tunnelUp        *prometheus.Desc
	tunnelBytes     *prometheus.Desc
	tunnelPackets   *prometheus.Desc
	tunnelLastRekey *prometheus.Desc
	uplinkRules     *prometheus.Desc
	uplinkTunnels   *prometheus.Desc
	hostfwInstalled *prometheus.Desc
	hostfwRules     *prometheus.Desc
	firewallFlows   *prometheus.Desc
	natDNAT         *prometheus.Desc
	natPoolSize     *prometheus.Desc
	pipelineHeld    *prometheus.Desc

	vpnLeases            *prometheus.Desc
	vpnAdmissions        *prometheus.Desc
	vpnRevocations       *prometheus.Desc
	vpnPostureViolations *prometheus.Desc
	vpnReattest          *prometheus.Desc
}

// NewCollector builds the gateway metrics collector over a snapshot source.
func NewCollector(source SnapshotSource) *Collector {
	name := func(sub, metric string) string {
		return prometheus.BuildFQName(metricNamespace, sub, metric)
	}
	return &Collector{
		source: source,
		serviceActive: prometheus.NewDesc(name("service", "active"),
			"1 when the service is running, 0 otherwise.", []string{"gateway", "service"}, nil),
		serviceHealthy: prometheus.NewDesc(name("service", "healthy"),
			"1 when the service reports itself healthy, 0 otherwise.", []string{"gateway", "service"}, nil),
		peerState: prometheus.NewDesc(name("bgp", "peer_established"),
			"1 when the BGP session is established, 0 otherwise.", []string{"gateway", "peer", "asn"}, nil),
		peerUptime: prometheus.NewDesc(name("bgp", "peer_uptime_seconds"),
			"How long the BGP session has been established.", []string{"gateway", "peer"}, nil),
		peerPrefixes: prometheus.NewDesc(name("bgp", "peer_prefixes"),
			"Prefixes on the session by direction: received, accepted or sent.", []string{"gateway", "peer", "direction"}, nil),
		bfdSessionUp: prometheus.NewDesc(name("bfd", "session_up"),
			"1 when the neighbour's BFD session is up, 0 otherwise.", []string{"gateway", "peer"}, nil),
		bfdFailures: prometheus.NewDesc(name("bfd", "failure_transitions_total"),
			"BFD session failures since the session was created.", []string{"gateway", "peer"}, nil),
		tunnelUp: prometheus.NewDesc(name("tunnel", "up"),
			"1 when the tunnel link is up, 0 otherwise.", []string{"gateway", "tunnel", "transport", "uplink"}, nil),
		tunnelBytes: prometheus.NewDesc(name("tunnel", "bytes_total"),
			"Bytes carried by the tunnel by direction.", []string{"gateway", "tunnel", "direction"}, nil),
		tunnelPackets: prometheus.NewDesc(name("tunnel", "packets_total"),
			"Packets carried by the tunnel by direction.", []string{"gateway", "tunnel", "direction"}, nil),
		tunnelLastRekey: prometheus.NewDesc(name("tunnel", "last_rekey_timestamp_seconds"),
			"When the tunnel's key material was last rotated; absent for a tunnel that has never been re-keyed.", []string{"gateway", "tunnel"}, nil),
		uplinkRules: prometheus.NewDesc(name("uplink", "policy_rules"),
			"Source policy rules programmed for the uplink.", []string{"gateway", "uplink", "table"}, nil),
		uplinkTunnels: prometheus.NewDesc(name("uplink", "bound_tunnels"),
			"Tunnels whose outer endpoints are pinned to the uplink's table.", []string{"gateway", "uplink"}, nil),
		hostfwInstalled: prometheus.NewDesc(name("hostfw", "installed"),
			"1 when the nftables host filter table is installed, 0 otherwise.", []string{"gateway", "fingerprint"}, nil),
		hostfwRules: prometheus.NewDesc(name("hostfw", "rules"),
			"Input rules in the applied host filter ruleset.", []string{"gateway"}, nil),
		firewallFlows: prometheus.NewDesc(name("firewall", "flows"),
			"Conntrack pipeline flows installed by the firewall service.", []string{"gateway"}, nil),
		natDNAT: prometheus.NewDesc(name("nat", "dnat_rules"),
			"Installed DNAT bindings.", []string{"gateway"}, nil),
		natPoolSize: prometheus.NewDesc(name("nat", "pool_addresses"),
			"IPv4 addresses in the uplink's SNAT pools.", []string{"gateway", "uplink"}, nil),
		pipelineHeld: prometheus.NewDesc(name("pipeline", "installed"),
			"1 while this gateway holds the base OVS pipeline on its bridge.", []string{"gateway", "bridge", "terminal"}, nil),
		vpnLeases: prometheus.NewDesc(name("vpn", "leases_active"),
			"Active remote-access VPN leases by data plane.", []string{"gateway", "data_plane"}, nil),
		vpnAdmissions: prometheus.NewDesc(name("vpn", "admissions_total"),
			"Remote-access VPN admission decisions by outcome: admitted or refused.", []string{"gateway", "outcome"}, nil),
		vpnRevocations: prometheus.NewDesc(name("vpn", "revocations_total"),
			"Revoked remote-access VPN leases by reason.", []string{"gateway", "reason"}, nil),
		vpnPostureViolations: prometheus.NewDesc(name("vpn", "posture_violations_total"),
			"Posture rules that refused a VPN admission or renewal, by rule; rules past the label bound count as other.", []string{"gateway", "rule"}, nil),
		vpnReattest: prometheus.NewDesc(name("vpn", "reattest_duration_seconds"),
			"How long a VPN lease renewal's re-attestation took to verify.", []string{"gateway"}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs() {
		ch <- d
	}
}

// descs lists every metric this collector can emit.
func (c *Collector) descs() []*prometheus.Desc {
	return []*prometheus.Desc{
		c.serviceActive, c.serviceHealthy, c.peerState, c.peerUptime, c.peerPrefixes,
		c.bfdSessionUp, c.bfdFailures, c.tunnelUp, c.tunnelBytes, c.tunnelPackets,
		c.tunnelLastRekey, c.uplinkRules, c.uplinkTunnels, c.hostfwInstalled,
		c.hostfwRules, c.firewallFlows, c.natDNAT, c.natPoolSize, c.pipelineHeld,
		c.vpnLeases, c.vpnAdmissions, c.vpnRevocations, c.vpnPostureViolations, c.vpnReattest,
	}
}

// Collect implements prometheus.Collector. A section the snapshot does not
// carry emits no series: an absent tunnel must not read as a tunnel that is
// down, and a service the gateway does not run must not read as unhealthy.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.source.Snapshot()
	if snap == nil {
		return
	}
	id := snap.GatewayID

	gauge := func(desc *prometheus.Desc, value float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labels...)
	}
	counter := func(desc *prometheus.Desc, value float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labels...)
	}

	for _, svc := range snap.Services {
		gauge(c.serviceActive, boolValue(svc.Active), id, svc.Name)
		gauge(c.serviceHealthy, boolValue(svc.Healthy), id, svc.Name)
	}

	for _, peer := range snap.BGP.Peers {
		gauge(c.peerState, boolValue(peer.State == peerStateEstablished), id, peer.Address, asnLabel(peer.ASN))
		gauge(c.peerUptime, float64(peer.UptimeSeconds), id, peer.Address)
		gauge(c.peerPrefixes, float64(peer.PrefixesReceived), id, peer.Address, "received")
		gauge(c.peerPrefixes, float64(peer.PrefixesAccepted), id, peer.Address, "accepted")
		gauge(c.peerPrefixes, float64(peer.PrefixesSent), id, peer.Address, "sent")
		if peer.BFD != nil {
			gauge(c.bfdSessionUp, boolValue(peer.BFD.State == bfdStateUp), id, peer.Address)
			counter(c.bfdFailures, float64(peer.BFD.FailureTransitions), id, peer.Address)
		}
	}

	for _, tun := range snap.Tunnels {
		gauge(c.tunnelUp, boolValue(tun.State == tunnelStateUp), id, tun.Name, tun.Transport, tun.Uplink)
		counter(c.tunnelBytes, float64(tun.RxBytes), id, tun.Name, "rx")
		counter(c.tunnelBytes, float64(tun.TxBytes), id, tun.Name, "tx")
		counter(c.tunnelPackets, float64(tun.RxPackets), id, tun.Name, "rx")
		counter(c.tunnelPackets, float64(tun.TxPackets), id, tun.Name, "tx")
		if !tun.LastRekey.IsZero() {
			gauge(c.tunnelLastRekey, float64(tun.LastRekey.Unix()), id, tun.Name)
		}
	}

	for _, up := range snap.Uplinks {
		gauge(c.uplinkRules, float64(up.RuleCount), id, up.Name, tableLabel(up.Table))
		gauge(c.uplinkTunnels, float64(len(up.Tunnels)), id, up.Name)
	}

	if snap.HostFirewall != nil {
		gauge(c.hostfwInstalled, boolValue(snap.HostFirewall.Installed), id, snap.HostFirewall.Fingerprint)
		gauge(c.hostfwRules, float64(snap.HostFirewall.RuleCount), id)
	}
	if snap.Firewall != nil {
		gauge(c.firewallFlows, float64(snap.Firewall.FlowCount), id)
	}
	if snap.NAT != nil {
		gauge(c.natDNAT, float64(snap.NAT.DNATRules), id)
		for _, up := range snap.NAT.Uplinks {
			gauge(c.natPoolSize, float64(up.PoolAddresses), id, up.Name)
		}
	}
	if snap.Pipeline != nil {
		gauge(c.pipelineHeld, boolValue(snap.Pipeline.Installed), id, snap.Pipeline.Bridge, snap.Pipeline.Terminal)
	}
	if snap.VPN != nil {
		c.collectVPN(ch, id, snap.VPN, gauge, counter)
	}
}

// collectVPN emits the remote-access VPN series of the telemetry section.
func (c *Collector) collectVPN(ch chan<- prometheus.Metric, id string, section *gwstate.VPNState,
	gauge, counter func(*prometheus.Desc, float64, ...string)) {
	for plane, n := range section.LeasesByDataPlane {
		gauge(c.vpnLeases, float64(n), id, plane)
	}
	counter(c.vpnAdmissions, float64(section.Admissions), id, "admitted")
	counter(c.vpnAdmissions, float64(section.Refusals), id, "refused")
	for reason, n := range section.Revocations {
		counter(c.vpnRevocations, float64(n), id, reason)
	}
	for rule, n := range section.PostureViolations {
		counter(c.vpnPostureViolations, float64(n), id, rule)
	}
	if h := section.Reattest; h != nil {
		buckets := make(map[float64]uint64, len(h.Buckets))
		for _, b := range h.Buckets {
			buckets[b.UpperBoundSeconds] = b.Count
		}
		ch <- prometheus.MustNewConstHistogram(c.vpnReattest, h.Count, h.SumSeconds, buckets, id)
	}
}

// Metric label and value constants shared with the snapshot vocabulary.
const (
	peerStateEstablished = "Established"
	bfdStateUp           = "up"
	tunnelStateUp        = "up"
)

// asnLabel renders an AS number as a label value.
func asnLabel(asn uint32) string { return strconv.FormatUint(uint64(asn), 10) }

// tableLabel renders a routing table id as a label value.
func tableLabel(table int) string { return strconv.Itoa(table) }

// boolValue maps a boolean onto the 1/0 a Prometheus gauge carries.
func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
