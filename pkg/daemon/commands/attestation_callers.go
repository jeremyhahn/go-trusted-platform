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

package commands

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// Sources recorded on the caller policy's Describe output, so an operator
// reading GET /api/v1/attestation/callers knows where each input came from.
const (
	callerIdentitiesConfigured = "configured:attestation.reporting.callers.reporting-servers"
	callerIdentitiesDerived    = "derived:acme.client.directory"
	callerAnchorsCAFile        = "attestation.reporting.callers.ca-file"
	callerAnchorsHeartbeatCA   = "heartbeat.ca-file"
	callerAnchorsPlatform      = "platform-anchor"
)

// callerPolicyInputs is everything the policy needs from the running node,
// gathered by initCallerPolicy so the build itself is a pure function that
// tests can drive without an App.
type callerPolicyInputs struct {
	// Callers is the configured section; nil selects every default.
	Callers *config.CallerAdmissionConfig
	// ACMEDirectory is the node's acme.client.directory URL. Its host is
	// the control plane this node enrolled against, and therefore the
	// default reporting-server identity.
	ACMEDirectory string
	// HeartbeatCAFile is heartbeat.ca-file: the CA the node already trusts
	// for the control plane it reports liveness to.
	HeartbeatCAFile string
	// PlatformAnchor is the platform CA — the root of the chain that issued
	// this node's IDevID — or nil when the node has no TPM identity.
	PlatformAnchor *trust.Anchor
	// Auditor receives every decision.
	Auditor calleradmission.Auditor
	// AttestedPeers backs the any-attested strategy; nil on a node that
	// holds no attested-peer evidence.
	AttestedPeers calleradmission.AttestedPeers
	Logger        *slog.Logger
}

// buildCallerPolicy compiles the node's caller-admission policy.
//
// Identity list: an operator-set `reporting-servers` list REPLACES the
// derived default entirely (owner ruling 2026-09-05) — it never unions with
// it, so an operator who names one server has named exactly one server.
// Anchors, in order: `callers.ca-file`, then `heartbeat.ca-file`, then the
// platform anchor. Whatever is used is logged and reported.
func buildCallerPolicy(in callerPolicyInputs) (*calleradmission.Policy, error) {
	logger := in.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cfg := in.Callers
	strategy := calleradmission.Strategy(cfg.EffectiveStrategy())

	identities, identitiesSource := callerIdentities(cfg, in.ACMEDirectory)
	anchors, anchorSource, err := callerAnchors(cfg, in.HeartbeatCAFile, in.PlatformAnchor)
	if err != nil {
		return nil, err
	}

	var allowlist []string
	if cfg != nil {
		allowlist = cfg.Allowlist
	}
	policy, err := calleradmission.New(calleradmission.Config{
		Strategy:               strategy,
		ReportingServers:       identities,
		ReportingServersSource: identitiesSource,
		Allowlist:              allowlist,
		Anchors:                anchors,
		AnchorSource:           anchorSource,
		AttestedPeers:          in.AttestedPeers,
		Auditor:                in.Auditor,
		Logger:                 logger,
	})
	if err != nil {
		return nil, err
	}
	desc := policy.Describe()
	logger.Info("attestation caller admission: effective policy",
		"strategy", string(desc.Strategy),
		"identities", desc.Identities,
		"identities_source", desc.IdentitiesSource,
		"list_valid", desc.ListValid,
		"anchors", len(anchors),
		"anchor_source", desc.AnchorSource,
		"attested_peers_available", desc.AttestedPeersAvailable,
		"admits_nobody", desc.AdmitsNobody)
	return policy, nil
}

// callerIdentities returns the reporting-server identity set and its
// source.
func callerIdentities(cfg *config.CallerAdmissionConfig, acmeDirectory string) ([]string, string) {
	if cfg != nil && len(cfg.ReportingServers) > 0 {
		return cfg.ReportingServers, callerIdentitiesConfigured
	}
	host := acmeDirectoryHost(acmeDirectory)
	if host == "" {
		return nil, callerIdentitiesDerived
	}
	return []string{host}, callerIdentitiesDerived
}

// acmeDirectoryHost returns the host name of the ACME directory URL, or
// empty when there is none or it is not a name (an IP literal is not a
// certificate identity the platform issues for).
func acmeDirectoryHost(directory string) string {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return ""
	}
	u, err := url.Parse(directory)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

// callerAnchors returns the CA certificates a caller must chain to, with
// the source used. A configured file that cannot be read or parsed is an
// error rather than a silent fall-through: an operator who named a file
// meant that file.
func callerAnchors(cfg *config.CallerAdmissionConfig, heartbeatCAFile string, anchor *trust.Anchor) ([]*x509.Certificate, string, error) {
	if cfg != nil && strings.TrimSpace(cfg.CAFile) != "" {
		certs, err := readCABundle(cfg.CAFile)
		if err != nil {
			return nil, "", ErrCallerAnchorsUnreadable{Path: cfg.CAFile, Cause: err}
		}
		return certs, callerAnchorsCAFile, nil
	}
	if strings.TrimSpace(heartbeatCAFile) != "" {
		certs, err := readCABundle(heartbeatCAFile)
		if err != nil {
			return nil, "", ErrCallerAnchorsUnreadable{Path: heartbeatCAFile, Cause: err}
		}
		return certs, callerAnchorsHeartbeatCA, nil
	}
	if anchor != nil {
		// A node that has not enrolled has no platform anchor yet; its
		// policy then admits nobody, which is reported rather than hidden.
		if certs, err := anchor.Certificates(context.Background()); err == nil {
			return certs, callerAnchorsPlatform, nil
		}
	}
	return nil, "", nil
}

// readCABundle parses every CA certificate in a PEM bundle.
func readCABundle(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if !cert.IsCA {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, ErrCallerAnchorsEmpty{Path: path}
	}
	return certs, nil
}

// initCallerPolicy builds the node's caller-admission policy from the
// running App. It returns nil, and logs why, only when there is nothing to
// build against; a nil policy leaves the quote routes operator-only.
func initCallerPolicy(logger *slog.Logger, a *app.App, svcs *attestationServices) *restattestation.Reporting {
	return initCallerPolicyWithPeers(logger, a, svcs, nil)
}

// withCollectorSurface merges the collector's report view and refresher
// into the REST surface and rebuilds the caller policy with the
// collector's attested-peer source, so any-attested works on the node that
// holds the cache.
func withCollectorSurface(logger *slog.Logger, rest *restattestation.Reporting, rep *reportingComponents, a *app.App, svcs *attestationServices) *restattestation.Reporting {
	rebuilt := initCallerPolicyWithPeers(logger, a, svcs, rep.AttestedPeers)
	out := &restattestation.Reporting{Reports: rep.Rest.Reports, Refresher: rep.Rest.Refresher}
	switch {
	case rebuilt != nil:
		out.Policy = rebuilt.Policy
		out.Clock = rebuilt.Clock
	case rest != nil:
		out.Policy = rest.Policy
		out.Clock = rest.Clock
	}
	return out
}

func initCallerPolicyWithPeers(logger *slog.Logger, a *app.App, svcs *attestationServices, peers calleradmission.AttestedPeers) *restattestation.Reporting {
	if a == nil {
		return nil
	}
	in := callerPolicyInputs{Logger: logger, AttestedPeers: peers}
	if a.AttestationConfig.Reporting != nil {
		in.Callers = a.AttestationConfig.Reporting.Callers
	}
	if a.ACMEConfig != nil && a.ACMEConfig.Client != nil {
		in.ACMEDirectory = a.ACMEConfig.Client.DirectoryURL
	}
	if a.HeartbeatConfig != nil {
		in.HeartbeatCAFile = a.HeartbeatConfig.CAFile
	}
	if a.TPM != nil && a.CA != nil {
		anchor, err := a.PlatformAnchor()
		if err != nil {
			logger.Error("attestation caller admission: platform anchor unavailable", "error", err)
		}
		in.PlatformAnchor = anchor
	}
	if svcs != nil && svcs.Service != nil {
		in.Auditor = svcs.Service
	}
	// The clock reader is wired here rather than beside the collector
	// because EVERY node serves the clock route — a worker holds no report
	// cache but is exactly the machine whose clock the control plane needs
	// to know about (#509).
	clock := newNTPClockAdapter(nodeClockStatusReader(a))

	policy, err := buildCallerPolicy(in)
	if err != nil {
		logger.Error("attestation caller admission: policy could not be built; quote routes stay operator-only",
			"error", err)
		// The policy and the clock are independent: a node whose policy
		// could not be built still answers its own clock state to an
		// operator, and the route is what says so.
		if clock == nil {
			return nil
		}
		return &restattestation.Reporting{Clock: clock}
	}
	return &restattestation.Reporting{Policy: policy, Clock: clock}
}

// nodeClockStatusReader returns this node's time service as the narrow
// status reader, or nil when no time service is running. It returns an
// untyped nil so a nil *ntp.Service never reaches the adapter as a non-nil
// interface.
func nodeClockStatusReader(a *app.App) clockStatusReader {
	if a == nil || a.NTPService == nil {
		return nil
	}
	return a.NTPService
}

// ErrCallerAnchorsUnreadable reports a configured anchor bundle that could
// not be used.
type ErrCallerAnchorsUnreadable struct {
	Path  string
	Cause error
}

func (e ErrCallerAnchorsUnreadable) Error() string {
	return "attestation caller admission: anchor bundle " + e.Path + " is unusable: " + e.Cause.Error()
}

func (e ErrCallerAnchorsUnreadable) Unwrap() error { return e.Cause }

// ErrCallerAnchorsEmpty reports a bundle with no CA certificate in it.
type ErrCallerAnchorsEmpty struct {
	Path string
}

func (e ErrCallerAnchorsEmpty) Error() string {
	return "attestation caller admission: anchor bundle " + e.Path + " contains no CA certificate"
}
