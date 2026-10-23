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
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
)

// gatewayControlPlane bundles the two halves of the CP-side gateway
// control surface — the cached telemetry store + the desired-config
// source — so the serve.go wiring code can hand them to the
// HandlerRegistry as a pair.
type gatewayControlPlane struct {
	Store      *gwstate.FileStore
	DesiredCfg *viperDesiredConfigSource
}

// initGatewayControlPlane stands up the telemetry store under
// <PlatformDir>/gateway/state and wires the Viper-backed desired-
// config source. Failures are non-fatal: the daemon continues
// without the surface and clients see the structured 503 envelope.
func initGatewayControlPlane(logger *logging.Logger, a *app.App) *gatewayControlPlane {
	if a == nil {
		return nil
	}
	root := filepath.Join(a.PlatformDir, "gateway", "state")
	store, err := gwstate.NewFileStore(root)
	if err != nil {
		logger.Warnf("gateway control plane: store unavailable: %v", err)
		return nil
	}
	logger.Info("gateway control plane wired", "state_root", root)
	return &gatewayControlPlane{
		Store:      store,
		DesiredCfg: &viperDesiredConfigSource{v: viper.GetViper()},
	}
}

// gatewayControlDaemon is the part of the daemon the gateway control plane
// is wired into.
type gatewayControlDaemon interface {
	GatewayGRPCService() *daemon.GatewayService
	VPNControlPlane() *vpn.Service
	RESTServer() *daemon.RESTServer
}

// wireGatewayControlPlane connects the gateway control plane to the daemon.
// The telemetry store backs the snapshot RPCs on every transport, so the
// control plane answers `GetGatewaySnapshot` from the same reports
// POST /gateway/telemetry writes (#594). VPN session status reads the vpn
// section of the same reports, and the enrolment set and posture policies
// reach the gateways as the vpn section of their desired configuration.
//
// When the daemon serves REST itself (no webservice listener), the
// gatewayd-facing routes are mounted on it, so the gateways' reports still
// have somewhere to land (docs/gateway/api.md). A nil control plane wires
// nothing.
func wireGatewayControlPlane(logger *logging.Logger, d gatewayControlDaemon, gw *gatewayControlPlane) {
	if gw == nil || gw.Store == nil {
		return
	}
	if svc := d.GatewayGRPCService(); svc != nil {
		svc.SetGatewaySnapshotStore(gw.Store)
	}
	vpnControl := d.VPNControlPlane()
	if vpnControl != nil {
		vpnControl.SetGatewaySnapshotStore(gw.Store)
		if gw.DesiredCfg != nil {
			gw.DesiredCfg.SetVPNSource(vpnControl)
		}
	}
	rest := d.RESTServer()
	if rest == nil {
		return
	}
	var cfgSource restgateway.DesiredConfigSource
	if gw.DesiredCfg != nil {
		cfgSource = gw.DesiredCfg
	}
	cp := restgateway.NewControlPlane(logger, gw.Store, cfgSource, response.NewResponseWriter(logger, nil))
	if vpnControl != nil {
		cp.SetVPNLeaseSink(vpnControl)
	}
	rest.SetGatewayControlPlane(cp)
}

// viperDesiredConfigSource resolves the control plane's intended
// configuration for a gatewayd from the platform's active Viper config
// tree (#555). The document is the typed wire contract
// (gwstate.DesiredConfig): only sections a gateway can apply through a
// live service exist in it, and each is decoded from the
// `gateway.desired:` block of the control plane's configuration —
// `gateway.desired.load-balancer.vips` and `gateway.desired.nat` — with
// `gateway.desired.version` as the operator's revision when set,
// otherwise the gateway derives one from the content.
//
// gatewayID is advisory: the same intent is served to every gatewayd
// until the deployment grows a second gateway and per-gateway overrides
// with it.
//
// The vpn section is not configuration: it is the enrolment set and the
// posture policies operators manage through VPNService, so once a VPN
// source is wired it is the section's only author.
type viperDesiredConfigSource struct {
	// v is the configuration tree to read; the platform's global instance
	// in the daemon, a private one in tests.
	v *viper.Viper
	// vpn supplies the vpn section; nil serves the document without one.
	vpn desiredVPNSource
}

// desiredVPNSource produces the vpn section of a gateway's desired
// configuration (pkg/vpn.Service).
type desiredVPNSource interface {
	DesiredVPN(ctx context.Context, gatewayID string) (*gwstate.DesiredVPN, error)
}

// SetVPNSource makes source the author of the vpn section.
func (v *viperDesiredConfigSource) SetVPNSource(source desiredVPNSource) {
	v.vpn = source
}

// desiredConfigKey is the Viper key holding the fleet's desired gateway
// configuration.
const desiredConfigKey = "gateway.desired"

// DesiredConfig satisfies restgateway.DesiredConfigSource.
func (v *viperDesiredConfigSource) DesiredConfig(gatewayID string) (*gwstate.DesiredConfig, error) {
	desired := &gwstate.DesiredConfig{GatewayID: gatewayID}
	tree := v.v
	if tree == nil {
		tree = viper.GetViper()
	}
	if tree.IsSet(desiredConfigKey) {
		if err := tree.UnmarshalKey(desiredConfigKey, desired); err != nil {
			return nil, &ErrDesiredConfigDecode{Key: desiredConfigKey, Cause: err}
		}
		desired.GatewayID = gatewayID
	}
	if err := v.overlayVPN(desired); err != nil {
		return nil, err
	}
	if err := desired.Validate(); err != nil {
		return nil, err
	}
	return desired, nil
}

// desiredVPNKey is the Viper key a vpn section would be configured under,
// which the VPN source refuses.
const desiredVPNKey = desiredConfigKey + ".vpn"

// overlayVPN sets the vpn section from the VPN source. An operator version
// is suffixed with the content version, because the gateway re-applies only
// when the version changes and an enrolment or a revocation does not change
// what the operator wrote.
func (v *viperDesiredConfigSource) overlayVPN(desired *gwstate.DesiredConfig) error {
	if v.vpn == nil {
		return nil
	}
	if desired.VPN != nil {
		return &ErrDesiredVPNConfigured{Key: desiredVPNKey}
	}
	section, err := v.vpn.DesiredVPN(context.Background(), desired.GatewayID)
	if err != nil {
		return err
	}
	desired.VPN = section
	if desired.Version != "" {
		desired.Version += "+vpn." + desired.ContentVersion()
	}
	return nil
}

// ErrDesiredConfigDecode reports a `gateway.desired:` block that does not
// decode as the wire contract.
type ErrDesiredConfigDecode struct {
	Key   string
	Cause error
}

// Error implements the error interface.
func (e *ErrDesiredConfigDecode) Error() string {
	return "gateway control plane: " + e.Key + " does not decode as a desired config: " + e.Cause.Error()
}

// Unwrap returns the decode failure.
func (e *ErrDesiredConfigDecode) Unwrap() error { return e.Cause }

// ErrDesiredVPNConfigured reports a vpn section in the configuration file
// while VPNService authors it: serving either would silently discard the
// other.
type ErrDesiredVPNConfigured struct {
	Key string
}

// Error implements the error interface.
func (e *ErrDesiredVPNConfigured) Error() string {
	return "gateway control plane: " + e.Key + " is managed through VPNService (platformctl vpn); remove it from the configuration"
}
