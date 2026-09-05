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
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// The attestation reporting collector (#226 slices B/D/E, control-plane
// side): dials every attestable device on a schedule, verifies what comes
// back, and serves the cached verdict with its age. This file composes it
// from the running App; the pieces themselves live in
// pkg/attestation/reporting and are tested there.

// reportingComponents is what the wiring hands the rest of serve.
type reportingComponents struct {
	// Handles go to the gRPC/Unix and MCP transports through daemon.Config.
	Handles *daemon.ReportingHandles
	// Rest goes to the webservice registry; the caller policy is added to
	// it after the policy is built (the policy consults the cache).
	Rest *restattestation.Reporting
	// AttestedPeers backs the any-attested strategy on this node.
	AttestedPeers calleradmission.AttestedPeers
	// Stop cancels the collector loop.
	Stop context.CancelFunc
}

// initReportingCollector builds and starts the collector when
// attestation.reporting.enabled is set. It returns nil, and says why, when
// the service is off or cannot be built; a nil result leaves every report
// transport answering "not configured", never a synthesised verdict.
func initReportingCollector(ctx context.Context, logger *slog.Logger, a *app.App, cfg *daemon.Config, svcs *attestationServices) *reportingComponents {
	if a == nil || cfg == nil {
		return nil
	}
	rc := a.AttestationConfig.Reporting
	if rc == nil || !rc.Enabled {
		logger.Info("attestation reporting: collector disabled on this node (attestation.reporting.enabled is false)")
		return nil
	}
	if cfg.DeviceService == nil {
		logger.Error("attestation reporting: collector enabled but no device service is configured; not started")
		return nil
	}

	var verdicts verdict.Sink
	if svcs != nil && svcs.Service != nil {
		verdicts = svcs.Service
	}
	var akTrust daemon.AKTrustAnchor
	if cfg.CAService != nil {
		akTrust = cfg.CAService
	}
	verifier, err := daemon.DeviceQuoteVerifierForReporting(cfg.DeviceService, cfg.DeviceProfileService, akTrust, verdicts, logger)
	if err != nil {
		logger.Error("attestation reporting: verifier unavailable; collector not started", "error", err)
		return nil
	}

	cache := reporting.NewCache(rc.EffectiveTTL())
	if svcs != nil && svcs.Service != nil {
		if st, ok := svcs.Service.Store().(reporting.Store); ok {
			if err := cache.Persist(st, logger); err != nil {
				logger.Error("attestation reporting: persisted reports unavailable; serving an empty cache until the first cycle", "error", err)
			}
		}
	}

	records := &deviceRecordsAdapter{devices: cfg.DeviceService}
	if cfg.DeviceProfileService != nil {
		records.profiles = cfg.DeviceProfileService
	}
	var names reporting.NameResolver
	internalDomain := ""
	if a.DNSService != nil {
		names = a.DNSService
		internalDomain = a.DNSService.InternalDomain()
	}
	addresses, err := reporting.NewDeviceAddressResolver(reporting.DeviceAddressResolverConfig{
		Devices:        records,
		Names:          names,
		InternalDomain: internalDomain,
		Port:           rc.Collector.EffectivePort(),
	})
	if err != nil {
		logger.Error("attestation reporting: address resolver unavailable; collector not started", "error", err)
		return nil
	}

	dialer, err := collectorTLSDialer(a, rc.Collector, logger)
	if err != nil {
		logger.Error("attestation reporting: collector identity unavailable; collector not started", "error", err)
		return nil
	}
	source, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: addresses,
		TLS:       dialer,
		Timeout:   rc.Collector.EffectiveTimeout(),
		PCRs:      collectorPCRs(rc.Collector),
		Logger:    logger,
	})
	if err != nil {
		logger.Error("attestation reporting: quote source unavailable; collector not started", "error", err)
		return nil
	}

	collector, err := reporting.NewCollector(reporting.Config{
		Source:   source,
		Verifier: verifier,
		Devices:  &attestableDevices{devices: cfg.DeviceService},
		Cache:    cache,
		Interval: rc.EffectiveInterval(),
		Logger:   logger,
	})
	if err != nil {
		logger.Error("attestation reporting: collector could not be built", "error", err)
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	go func() {
		if err := collector.Run(runCtx); err != nil && runCtx.Err() == nil {
			logger.Error("attestation reporting: collector stopped", "error", err)
		}
	}()
	logger.Info("attestation reporting: collector started",
		"interval", rc.EffectiveInterval().String(),
		"ttl", rc.EffectiveTTL().String(),
		"port", rc.Collector.EffectivePort(),
		"persisted_reports", cache.Len())

	return &reportingComponents{
		Handles:       &daemon.ReportingHandles{Reports: cache, Refresher: collector},
		Rest:          &restattestation.Reporting{Reports: cache, Refresher: collector},
		AttestedPeers: &attestedPeersAdapter{devices: cfg.DeviceService, reports: cache},
		Stop:          cancel,
	}
}

// collectorPCRs returns the configured PCR selection, or nil for the node
// default.
func collectorPCRs(c *config.CollectorConfig) []int {
	if c == nil {
		return nil
	}
	return c.PCRs
}

// collectorIdentityName resolves which webservice's key and certificate the
// collector presents: the configured name, else the primary webservice,
// else the "default" key the serve loop uses for an unnamed webservice.
func collectorIdentityName(a *app.App, c *config.CollectorConfig) string {
	if c != nil && strings.TrimSpace(c.Identity) != "" {
		return strings.TrimSpace(c.Identity)
	}
	if primary := a.PrimaryWebService(); primary != nil && primary.Name != "" {
		return primary.Name
	}
	return "default"
}

// collectorTLSDialer returns the per-endpoint TLS builder: this node's
// webservice identity as the client certificate (with the platform
// intermediate in the chain, so a node anchored only on the root can
// verify it) and the trust resolver's internal class for the node's
// certificate. It fails at wiring time when the identity does not exist,
// and at dial time when the trust class cannot be resolved — never by
// dialling unverified.
func collectorTLSDialer(a *app.App, c *config.CollectorConfig, logger *slog.Logger) (reporting.TLSDialer, error) {
	if a.CA == nil {
		return nil, ErrCollectorIdentity{Reason: "no certificate authority is initialised"}
	}
	name := collectorIdentityName(a, c)
	attrs, ok := a.WebServiceKeyAttributes[name]
	if !ok || attrs == nil {
		return nil, ErrCollectorIdentity{Reason: "no webservice named " + strconv.Quote(name) + " holds a key (attestation.reporting.collector.identity)"}
	}
	anchors, err := collectorAnchors(a, c, logger)
	if err != nil {
		return nil, err
	}
	ca := a.CA
	return func(ctx context.Context, ep reporting.Endpoint) (*tls.Config, error) {
		cert, err := ca.TLSCertificate(ctx, attrs)
		if err != nil {
			return nil, ErrCollectorIdentity{Reason: "client certificate unavailable: " + err.Error()}
		}
		if len(cert.Certificate) == 1 {
			if inter, err := ca.TrustedIntermediate(); err == nil && inter != nil {
				cert.Certificate = append(cert.Certificate, inter.Raw)
			}
		}
		pool, err := anchors(ctx, ep)
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, ErrCollectorIdentity{Reason: "no anchors resolved for the node's certificate"}
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   ep.ServerName,
			MinVersion:   tls.VersionTLS12,
		}, nil
	}, nil
}

// profileMatcher is the one profile-service method the adapter needs.
type profileMatcher interface {
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)
}

// collectorAnchorSource is a per-endpoint pool provider.
type collectorAnchorSource func(ctx context.Context, ep reporting.Endpoint) (*x509.CertPool, error)

// collectorAnchors selects where the node's certificate is verified
// against, in the same order the gateway reporter uses for the control
// plane (pkg/sdn/gateway/commands/reporter.go): an explicit
// `collector.ca-file` first, else the trust resolver's `internal` class.
// A configured file that cannot be used is an error, not a fall-through;
// with neither, the collector is not started.
func collectorAnchors(a *app.App, c *config.CollectorConfig, logger *slog.Logger) (collectorAnchorSource, error) {
	if c != nil && strings.TrimSpace(c.CAFile) != "" {
		certs, err := readCABundle(c.CAFile)
		if err != nil {
			return nil, ErrCollectorIdentity{Reason: "node anchor bundle " + c.CAFile + " is unusable: " + err.Error()}
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		logger.Info("attestation reporting: node certificates are verified against an operator bundle",
			"ca_file", c.CAFile, "anchors", len(certs))
		return func(context.Context, reporting.Endpoint) (*x509.CertPool, error) { return pool, nil }, nil
	}
	resolver := a.TrustResolver()
	if resolver == nil {
		return nil, ErrCollectorIdentity{Reason: "no trust resolver is configured; set trust.internal or attestation.reporting.collector.ca-file to say what node certificates must chain to"}
	}
	logger.Info("attestation reporting: node certificates are verified against the trust resolver", "class", string(trust.ClassInternal))
	return func(ctx context.Context, ep reporting.Endpoint) (*x509.CertPool, error) {
		return resolver.CAPool(ctx, trust.ClassInternal, ep.Address)
	}, nil
}

// deviceRecordsAdapter reads what the address resolver needs from the
// device and profile services.
type deviceRecordsAdapter struct {
	devices  device.DeviceService
	profiles profileMatcher
}

func (d *deviceRecordsAdapter) AddressRecord(ctx context.Context, deviceID string) (*reporting.DeviceAddressRecord, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(deviceID), 10, 64)
	if err != nil {
		return nil, ErrCollectorDeviceID{DeviceID: deviceID}
	}
	dev, err := d.devices.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	rec := &reporting.DeviceAddressRecord{Hostname: dev.Hostname, HeartbeatAddr: dev.LastHeartbeatAddr}
	if d.profiles != nil {
		if profile, err := d.profiles.FindMatchingProfile(ctx, "", dev.Serial, dev.Model); err == nil && profile != nil {
			rec.TLSServerName = profile.TLSServerName
		}
	}
	return rec, nil
}

// attestableDevices lists the devices the collector should attest: every
// device with an enrolled attestation key that is not revoked or
// suspended. A quarantined device stays on the list so a passing verdict
// can lift the quarantine.
type attestableDevices struct {
	devices device.DeviceService
}

const attestablePageSize = 200

func (l *attestableDevices) AttestableDevices(ctx context.Context) ([]string, error) {
	var ids []string
	for page := 1; ; page++ {
		result, err := l.devices.Page(ctx, datastore.PageQuery{Page: page, PageSize: attestablePageSize, SortOrder: datastore.SortAscending})
		if err != nil {
			return nil, err
		}
		for _, dev := range result.Entities {
			if attestable(dev) {
				ids = append(ids, strconv.FormatUint(dev.ID, 10))
			}
		}
		if len(result.Entities) < attestablePageSize {
			break
		}
	}
	return ids, nil
}

func attestable(dev *entities.Device) bool {
	if dev == nil {
		return false
	}
	// The trust anchor the verifier uses is the enrolled attestation
	// certificate (#374), with the bare attestation key as the older
	// enrollment shape. A device with neither cannot be verified and is not
	// dialled: absence of an anchor is not a failed attestation.
	if strings.TrimSpace(dev.AttestCert) == "" && strings.TrimSpace(dev.AttestPub) == "" {
		return false
	}
	switch dev.State {
	case entities.DeviceStateRevoked, entities.DeviceStateSuspended:
		return false
	}
	return true
}

// attestedPeersAdapter answers the any-attested strategy from this node's
// own report cache: a peer is attested when a device carrying one of its
// certificate names has a verified, fresh report.
type attestedPeersAdapter struct {
	devices device.DeviceService
	reports reporting.Viewer
}

func (a *attestedPeersAdapter) PeerAttestation(names []string) (calleradmission.PeerAttestation, bool) {
	ctx := context.Background()
	for _, name := range names {
		dev := a.lookup(ctx, name)
		if dev == nil {
			continue
		}
		view, ok := a.reports.View(strconv.FormatUint(dev.ID, 10))
		if !ok {
			continue
		}
		return calleradmission.PeerAttestation{Verified: view.Verified, Fresh: view.Fresh}, true
	}
	return calleradmission.PeerAttestation{}, false
}

func (a *attestedPeersAdapter) lookup(ctx context.Context, name string) *entities.Device {
	if dev, err := a.devices.FindByHostname(ctx, name); err == nil && dev != nil {
		return dev
	}
	// A certificate name is an FQDN; the device hostname is the IDevID CN,
	// which may be the bare label.
	if i := strings.IndexByte(name, '.'); i > 0 {
		if dev, err := a.devices.FindByHostname(ctx, name[:i]); err == nil && dev != nil {
			return dev
		}
	}
	if dev, err := a.devices.FindBySerial(ctx, name); err == nil && dev != nil {
		return dev
	}
	return nil
}

// ErrCollectorIdentity reports the collector cannot present or verify an
// identity.
type ErrCollectorIdentity struct {
	Reason string
}

func (e ErrCollectorIdentity) Error() string {
	return "attestation reporting: collector identity: " + e.Reason
}

// ErrCollectorDeviceID reports a device id the collector cannot look up.
type ErrCollectorDeviceID struct {
	DeviceID string
}

func (e ErrCollectorDeviceID) Error() string {
	return "attestation reporting: device id " + strconv.Quote(e.DeviceID) + " is not a numeric device id"
}
