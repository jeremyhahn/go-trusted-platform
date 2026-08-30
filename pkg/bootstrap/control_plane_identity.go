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

package bootstrap

import (
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
)

// cpWebserviceTLSPort is the TLS port of the control plane's public
// webservice as the device template declares it (webservices[].tls-port).
// It selects which webservice entry's certificate identity the
// orchestrator verifies against. cpWebservicePort, the port actually
// dialed, defaults to it; tests redirect only the dial.
const cpWebserviceTLSPort = 8443

// controlPlaneTLSNameFallbackSource names the source recorded when the
// merged control-plane config carries no webservice certificate identity
// and the "cp." role alias under the platform domain is used instead.
const controlPlaneTLSNameFallbackSource = "platform.domain fallback"

// firstControlPlaneNode returns the first discovered control-plane node,
// or nil when discovery found none.
func (o *Orchestrator) firstControlPlaneNode() *DiscoveredNode {
	for i := range o.discovered {
		if o.discovered[i].Role == RoleControlPlane {
			return &o.discovered[i]
		}
	}
	return nil
}

// controlPlaneTLSName returns the DNS name every orchestrator TLS client
// verifies the control plane's certificate against, resolved once per
// orchestrator and logged once.
//
// The orchestrator dials the control plane by address, but the control
// plane's webservice certificate carries only DNS names — its subject CN
// and DNS SANs — never the IP it happens to listen on. Go verifies the
// certificate against the name the client asked for, so the expected name
// has to come from configuration: the merged control-plane config the
// orchestrator itself stages is the single source of truth (the subject CN,
// or failing that the first DNS SAN, of the webservices entry on
// cpWebserviceTLSPort). Only when that config carries no such name does the
// "cp." role alias under the platform domain stand in, logged at WARN. The
// node's hostname is never used: it is not what the certificate says.
func (o *Orchestrator) controlPlaneTLSName() (string, error) {
	o.cpTLSNameOnce.Do(func() {
		o.cpTLSName, o.cpTLSNameErr = o.resolveControlPlaneTLSName()
	})
	return o.cpTLSName, o.cpTLSNameErr
}

func (o *Orchestrator) resolveControlPlaneTLSName() (string, error) {
	if cpNode := o.firstControlPlaneNode(); cpNode != nil && o.config != nil {
		merged, err := o.resolveNodeConfig(cpNode.Hostname, RoleControlPlane)
		if err != nil {
			o.logger.Warn("bootstrap: control-plane TLS name: merged control-plane config unavailable, falling back to the cp role alias",
				slog.String("hostname", cpNode.Hostname),
				slog.String("error", err.Error()))
		} else if name, source := webserviceTLSNameFromConfig(merged, cpWebserviceTLSPort); name != "" {
			o.logger.Info("bootstrap: control-plane TLS name",
				slog.String("name", name),
				slog.String("source", source))
			return name, nil
		} else {
			o.logger.Warn("bootstrap: control-plane TLS name: merged control-plane config carries no webservice certificate name, falling back to the cp role alias",
				slog.String("hostname", cpNode.Hostname),
				slog.Int("tls_port", cpWebserviceTLSPort))
		}
	}
	domain := ""
	if o.config != nil {
		domain = strings.TrimSpace(o.config.Platform.Domain)
	}
	if domain == "" {
		return "", ControlPlaneTLSNameUnknownError{}
	}
	name := "cp." + domain
	o.logger.Warn("bootstrap: control-plane TLS name",
		slog.String("name", name),
		slog.String("source", controlPlaneTLSNameFallbackSource))
	return name, nil
}

// webserviceTLSNameFromConfig reads the certificate identity of the
// webservices entry listening on tlsPort out of a merged device config: the
// subject CN first, else the first DNS SAN. It returns the name and the
// config key it came from, or empty strings when the config carries none.
func webserviceTLSNameFromConfig(mergedYAML string, tlsPort int) (name, source string) {
	var cfg struct {
		Webservices []struct {
			TLSPort     int `yaml:"tls-port"`
			Certificate struct {
				Subject struct {
					CN string `yaml:"cn"`
				} `yaml:"subject"`
				SANs struct {
					DNS []string `yaml:"dns"`
				} `yaml:"sans"`
			} `yaml:"certificate"`
		} `yaml:"webservices"`
	}
	if err := yaml.Unmarshal([]byte(mergedYAML), &cfg); err != nil {
		return "", ""
	}
	for i, ws := range cfg.Webservices {
		if ws.TLSPort != tlsPort {
			continue
		}
		if cn := strings.TrimSpace(ws.Certificate.Subject.CN); cn != "" {
			return cn, fmt.Sprintf("webservices[%d].certificate.subject.cn", i)
		}
		for j, san := range ws.Certificate.SANs.DNS {
			if san = strings.TrimSpace(san); san != "" {
				return san, fmt.Sprintf("webservices[%d].certificate.sans.dns[%d]", i, j)
			}
		}
	}
	return "", ""
}

// controlPlaneDialCandidates lists the addresses at which to reach the
// control plane's webservice AFTER its CA pool has been captured, most
// likely first: the IP platformd reported in registration.json after
// first boot, the node's declared static IPv4s, then its hostname.
//
// registration.json is an unauthenticated PUT, so its address is never
// used to acquire trust material (fetchControlPlaneCABundle and
// fetchControlPlaneSPKIPin dial the static IPv4 only). Once the pool is
// pinned every connection verifies against it for controlPlaneTLSName, so
// a registration that points somewhere else yields a TLS failure and the
// next candidate is tried; the order affects reachability, not trust.
func (o *Orchestrator) controlPlaneDialCandidates(cpNode *DiscoveredNode) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if o.config != nil {
		if baseURL, err := installLogBaseURL(&o.config.Deployer); err == nil {
			if ip, err := fetchRegistrationIP(baseURL, cpNode.Hostname, allNodeMACs(cpNode)); err == nil {
				add(ip)
			}
		}
	}
	for _, ip := range cpNode.StaticIPv4s() {
		add(ip)
	}
	add(cpNode.Hostname)
	return out
}

// ControlPlaneTLSName is the exported form of controlPlaneTLSName for
// callers outside the orchestrator that reach the control plane over TLS
// with the pool from ControlPlaneCAPool: the pool alone is not enough,
// because the control plane's certificate names its DNS identity, not the
// address a caller dials.
func (o *Orchestrator) ControlPlaneTLSName() (string, error) {
	return o.controlPlaneTLSName()
}

// ControlPlaneAddresses is the exported form of controlPlaneDialCandidates
// for the given control-plane node: the addresses to try, most likely
// first, for connections that verify against the pool from
// ControlPlaneCAPool. Discover must have been called so registration
// lookups have the node's MACs.
func (o *Orchestrator) ControlPlaneAddresses(node *DiscoveredNode) []string {
	return o.controlPlaneDialCandidates(node)
}
