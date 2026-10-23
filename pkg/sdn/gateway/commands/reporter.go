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

package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// reporterHTTPTimeout bounds each telemetry POST and desired-config GET.
const reporterHTTPTimeout = 30 * time.Second

// snapshotCollector adapts the gateway node's Snapshot assembly to the
// controlplane.Collector interface.
type snapshotCollector struct {
	gw *gateway.Gateway
}

// Collect implements controlplane.Collector.
func (c *snapshotCollector) Collect(ctx context.Context) (*gwstate.Snapshot, error) {
	return c.gw.Snapshot(), nil
}

// BuildReporter constructs the control-plane telemetry reporter from the
// `control-plane:` configuration section. Returns (nil, nil) when the
// section is absent or disabled.
//
// The HTTP client presents the gateway's configured client certificate
// (its IDevID-derived platform identity) at TLS handshake time and
// anchors server verification on, in order of precedence: the explicit
// ca-file, the platform anchor when `platform-ca-file:` is configured, or
// the operating-system trust store.
func BuildReporter(ctx context.Context, cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) (*controlplane.Reporter, error) {
	if cfg == nil {
		return nil, ErrConfigLoadFailed
	}
	if logger == nil {
		logger = slog.Default()
	}
	cpCfg := cfg.ControlPlane
	if cpCfg == nil || !cpCfg.Enabled {
		return nil, nil
	}
	if err := cpCfg.Validate(); err != nil {
		return nil, &ErrConfigSection{Section: "control-plane", Cause: err}
	}

	gatewayID := cpCfg.GatewayID
	if gatewayID == "" {
		gatewayID = gw.GetConfig().ID
	}

	// An identity the control plane refuses on sight, whatever certificate
	// backs it. The CP will not accept a Common Name with leading or
	// trailing whitespace at all, so a gateway ID of that shape can only
	// ever 401 — including in the case the certificate CN matches it
	// exactly, which the CN comparison below would wave through. Running
	// before the certificate is even loaded is what makes that case
	// unreachable rather than merely unlikely.
	//
	// An empty ID is excluded here because it is not an identity the CP
	// rejects for its *shape*, and it is not reachable through the normal
	// path anyway: BuildGateway defaults an unset node ID. Should one
	// arrive, the CN comparison below reports it as a mismatch naming the
	// CN the certificate actually carries — a more useful message than
	// "GatewayID is missing". There is always a certificate to compare
	// against: Validate has already refused an enabled section without
	// cert-file.
	if gatewayID != "" && strings.TrimSpace(gatewayID) != gatewayID {
		return nil, &ErrGatewayIDNotReportable{GatewayID: gatewayID}
	}

	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		return nil, err
	}
	httpClient, certCN, err := buildReporterHTTPClient(ctx, cpCfg, anchor)
	if err != nil {
		return nil, err
	}

	// Fail fast on an identity the control plane will reject anyway.
	// The CP binds the reported gateway_id to this certificate's Common
	// Name, so a mismatch does not degrade — every telemetry push and
	// every desired-config fetch 403s, forever, and the only symptom is
	// a warning on a ticker. Refusing at assembly turns that into one
	// precise message before the daemon claims to be reporting.
	//
	// Gated on CertFile rather than on a non-empty CN: Validate already
	// mandates cert-file for an enabled section, so a certificate whose
	// CN is empty (or is only whitespace, which the CP refuses) must
	// fail here too rather than skip the check.
	if cpCfg.CertFile != "" && certCN != gatewayID {
		return nil, &ErrGatewayIDCertMismatch{
			GatewayID: gatewayID,
			CertCN:    certCN,
			CertFile:  cpCfg.CertFile,
		}
	}

	return controlplane.NewReporter(controlplane.ReporterConfig{
		CPBaseURL:  cpCfg.BaseURL,
		GatewayID:  gatewayID,
		Interval:   cpCfg.Interval,
		HTTPClient: httpClient,
		Collector:  &snapshotCollector{gw: gw},
		Logger:     logger,
	})
}

// buildReporterHTTPClient assembles the mTLS-bound HTTP client the
// reporter uses toward the control plane. It also returns the client
// certificate's Subject Common Name — the identity the control plane
// binds reported telemetry to — so the caller can reject a gateway-id /
// certificate mismatch before the reporter starts. The CN is empty when
// no client certificate is configured.
func buildReporterHTTPClient(ctx context.Context, cpCfg *controlplane.Config, anchor *trust.Anchor) (*http.Client, string, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	var certCN string
	if cpCfg.CertFile != "" {
		cert, err := loadNodeIdentity(cpCfg)
		if err != nil {
			return nil, "", err
		}
		certCN, err = clientCertCommonName(&cert)
		if err != nil {
			return nil, "", &proxysvc.ErrCertificateLoadFailed{CertFile: cpCfg.CertFile, Cause: err}
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	roots, err := reporterRootCAs(ctx, cpCfg, anchor)
	if err != nil {
		return nil, "", err
	}
	tlsCfg.RootCAs = roots // nil selects the operating-system trust store

	return &http.Client{
		Timeout: reporterHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, certCN, nil
}

// clientCertCommonName reads the Subject Common Name from a loaded
// keypair's leaf certificate. LoadX509KeyPair populates Leaf on current
// Go releases; the DER re-parse is the fallback for a tls.Certificate
// assembled without it, so this never silently reports an empty CN for a
// certificate that has one.
//
// The CN is returned verbatim. Trimming it would hide a padded CN from
// the gateway-id comparison here while the control plane refuses that
// same certificate, turning a startup error into a permanent 403.
func clientCertCommonName(cert *tls.Certificate) (string, error) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return "", ErrClientCertEmpty
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", err
		}
		leaf = parsed
	}
	return leaf.Subject.CommonName, nil
}

// reporterRootCAs resolves the CA pool anchoring control-plane server
// verification. An explicit ca-file wins; otherwise the platform anchor
// (`platform-ca-file:`) is used. With neither, nil selects the
// operating-system trust store.
func reporterRootCAs(ctx context.Context, cpCfg *controlplane.Config, anchor *trust.Anchor) (*x509.CertPool, error) {
	if cpCfg.CAFile != "" {
		pem, err := os.ReadFile(cpCfg.CAFile)
		if err != nil {
			return nil, &ErrCAFileLoadFailed{Path: cpCfg.CAFile, Cause: err}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &ErrCAFileLoadFailed{Path: cpCfg.CAFile}
		}
		return pool, nil
	}
	if anchor == nil {
		return nil, nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, trustResolveTimeout)
	defer cancel()
	return anchor.CAPool(resolveCtx)
}

// BuildReconciler constructs the desired-config reconcile loop from the
// `control-plane:` section, the reporter that fetches the document and
// the gateway that applies it (#555). It is only ever called with a
// non-nil reporter, i.e. an enabled section.
func BuildReconciler(cfg *ServeConfig, fetcher controlplane.DesiredConfigFetcher, gw *gateway.Gateway, logger *slog.Logger) (*controlplane.Reconciler, error) {
	if cfg == nil || cfg.ControlPlane == nil {
		return nil, ErrConfigLoadFailed
	}
	if logger == nil {
		logger = slog.Default()
	}
	reconciler, err := controlplane.NewReconciler(controlplane.ReconcilerConfig{
		Fetcher:  fetcher,
		Applier:  gw,
		Interval: cfg.ControlPlane.EffectiveReconcileInterval(),
		Logger:   logger,
	})
	if err != nil {
		return nil, &ErrConfigSection{Section: "control-plane", Cause: err}
	}
	return reconciler, nil
}
