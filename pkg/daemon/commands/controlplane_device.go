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
	"log/slog"
	"strconv"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// The control plane as a device in its own registry (#472, owner ruling
// 2026-09-06). This file is the composition: it reads the running App's own
// TPM identity, writes it through the same registration the ACME finalize
// hook uses (pkg/device), and hands the collector the one endpoint it
// cannot learn from DNS or a heartbeat — the control plane's own listener.
//
// Phase. Self-registration runs in the serve path, immediately before the
// collector is built, for two reasons that are not preferences:
//
//   - The device registry does not exist earlier. It is materialised by
//     App.ServiceRegistry(), which the serve path calls a few dozen lines
//     above; platform identity completion (pkg/app CompletePlatformIdentity,
//     where the IAK and IDevID certificates are issued) runs before the
//     datastore is up, so there is nothing to write to at that point.
//   - The record has to be a reconcile, not a one-shot at install. Every
//     control plane already deployed was provisioned before this existed
//     (#472 was measured on a running fleet), and a registration that only
//     happened at first boot would leave those machines permanently
//     unattestable. Running it on every start makes an existing control
//     plane acquire its record on the next restart, and device.Register is
//     find-or-create by product serial, so repeating it is a no-op.

// controlPlaneSelfDevice is what the serve path learned about this control
// plane's own device record and quote endpoint.
type controlPlaneSelfDevice struct {
	// DeviceID is the record's id, as the collector addresses devices.
	DeviceID string
	// Serial and Hostname are the record's identity, for the startup log
	// and the operator's `platformctl device` lookups.
	Serial   string
	Hostname string
	// Endpoint is where the collector dials this control plane for its own
	// quote.
	Endpoint reporting.SelfEndpoint
}

// initControlPlaneDevice registers the control plane as a device in its own
// registry and returns its self endpoint, or nil (with the reason logged)
// when there is nothing to register.
//
// It runs only where the collector runs. `attestation.reporting.enabled` is
// what makes a node a reporting server, and a self record is only useful
// where something collects it; a node that merely answers quotes holds no
// device registry of its own to appear in.
//
// A failure here never stops the daemon. The control plane serves the fleet
// whether or not it has its own record, and refusing to start because one
// machine's self-registration failed would take the whole platform down
// over a reporting gap.
func initControlPlaneDevice(ctx context.Context, logger *slog.Logger, a *app.App, cfg *daemon.Config) *controlPlaneSelfDevice {
	if a == nil || cfg == nil {
		return nil
	}
	rc := a.AttestationConfig.Reporting
	if rc == nil || !rc.Enabled {
		return nil
	}
	if cfg.DeviceService == nil {
		logger.Error("control plane device: no device registry is configured; the control plane cannot register itself")
		return nil
	}
	if a.TPM == nil {
		logger.Error("control plane device: no TPM is open; the control plane cannot register itself")
		return nil
	}
	return registerControlPlaneDevice(ctx, logger, a, cfg, a.TPM)
}

// registerControlPlaneDevice is initControlPlaneDevice past its gates,
// taking the TPM as the narrow surface the registrar actually reads so the
// whole path is exercisable without a TPM.
func registerControlPlaneDevice(ctx context.Context, logger *slog.Logger, a *app.App, cfg *daemon.Config, tpm device.ControlPlaneTPM) *controlPlaneSelfDevice {
	rc := a.AttestationConfig.Reporting
	discovered := xkmssdk.DiscoverPlatformAttributes()
	var discoveredModel, discoveredSerial string
	if discovered != nil {
		discoveredModel, discoveredSerial = discovered.Model, discovered.Serial
	}
	model, serial := resolveProductAttributes(a.TPMConfig.IDevID, discoveredModel, discoveredSerial)

	registrar, err := device.NewControlPlaneRegistrar(device.ControlPlaneRegistrarConfig{
		TPM:     tpm,
		Devices: cfg.DeviceService,
		Model:   model,
		Serial:  serial,
		Logger:  logger,
	})
	if err != nil {
		logger.Error("control plane device: the control plane cannot register itself as a device", "error", err)
		return nil
	}
	result, err := registrar.Register(ctx)
	if err != nil {
		logger.Error("control plane device: self-registration failed; the control plane will not be collected", "error", err)
		return nil
	}

	self := &controlPlaneSelfDevice{
		DeviceID: strconv.FormatUint(result.Device.ID, 10),
		Serial:   result.Device.Serial,
		Hostname: result.Device.Hostname,
	}
	host, port, serverName := controlPlaneQuoteEndpoint(a, rc.Collector)
	self.Endpoint = reporting.SelfEndpoint{
		DeviceID:   self.DeviceID,
		Host:       host,
		Port:       port,
		ServerName: serverName,
	}
	logger.Info("control plane device: registered; the collector will attest this control plane like any node",
		"device_id", self.DeviceID,
		"serial", self.Serial,
		"hostname", self.Hostname,
		"endpoint", host+":"+strconv.Itoa(port),
		"server_name", serverName)
	return self
}

// resolveProductAttributes applies the same config-first-then-SMBIOS
// precedence the TCG-CSR-IDEVID enrollment applies to a node's product
// model and serial, so the control plane's record carries the same values
// its own enrollment would have carried.
//
// It is spelled out here rather than called because the upstream helper
// (go-xkms tpm2.ResolvePlatformAttributes) is not among the quicbaas SDK
// re-exports; only the discovery half is. That is a small SDK gap, recorded
// in the PR, not a licence to reach around the SDK — the discovery result is
// still the SDK's.
func resolveProductAttributes(cfg *xkmssdk.IDevIDConfig, discoveredModel, discoveredSerial string) (string, string) {
	model, serial := discoveredModel, discoveredSerial
	if cfg != nil {
		if v := strings.TrimSpace(cfg.Model); v != "" {
			model = v
		}
		if v := strings.TrimSpace(cfg.Serial); v != "" {
			serial = v
		}
	}
	return strings.TrimSpace(model), strings.TrimSpace(serial)
}

// controlPlaneQuoteEndpoint returns where the collector dials this control
// plane for its own quote: the loopback interface, the TLS port of the
// webservice whose identity the collector presents, and the name that
// webservice's certificate carries.
//
// The webservice is the same one collectorIdentityName selects, so the
// collector presents the identity belonging to the listener it is calling —
// on a control plane serving a public and an internal listener, that keeps
// the self-collection entirely on the internal one.
func controlPlaneQuoteEndpoint(a *app.App, c *config.CollectorConfig) (string, int, string) {
	ws := controlPlaneWebService(a, c)
	port := 0
	serverName := ""
	if ws != nil {
		switch {
		case ws.TLSPort > 0:
			port = ws.TLSPort
		case ws.Port > 0:
			port = ws.Port
		}
		serverName = webServiceCertificateName(ws)
	}
	if port <= 0 {
		port = c.EffectivePort()
	}
	return reporting.DefaultSelfHost, port, serverName
}

// controlPlaneWebService returns the webservice the collector's identity
// belongs to, else the primary one.
func controlPlaneWebService(a *app.App, c *config.CollectorConfig) *v1.Config {
	name := collectorIdentityName(a, c)
	for _, ws := range a.WebServices {
		if ws != nil && ws.Name == name {
			return ws
		}
	}
	if ws := a.WebServiceConfig; ws != nil && ws.Name == name {
		return ws
	}
	return a.PrimaryWebService()
}

// webServiceCertificateName returns the name a webservice's certificate is
// issued for: the subject Common Name, else its first DNS SAN. Empty when
// the webservice declares neither, in which case the address resolver falls
// back to the device's own FQDN and refuses if there is not one.
func webServiceCertificateName(ws *v1.Config) string {
	if ws == nil {
		return ""
	}
	if cn := strings.TrimSpace(ws.Certificate.Subject.CommonName); cn != "" {
		return cn
	}
	if ws.Certificate.SANS == nil {
		return ""
	}
	for _, dns := range ws.Certificate.SANS.DNS {
		if name := strings.TrimSpace(dns); name != "" {
			return name
		}
	}
	return ""
}
