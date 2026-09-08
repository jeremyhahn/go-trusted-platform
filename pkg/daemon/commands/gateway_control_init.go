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
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
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
type viperDesiredConfigSource struct {
	// v is the configuration tree to read; the platform's global instance
	// in the daemon, a private one in tests.
	v *viper.Viper
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
	if !tree.IsSet(desiredConfigKey) {
		return desired, nil
	}
	if err := tree.UnmarshalKey(desiredConfigKey, desired); err != nil {
		return nil, &ErrDesiredConfigDecode{Key: desiredConfigKey, Cause: err}
	}
	desired.GatewayID = gatewayID
	if err := desired.Validate(); err != nil {
		return nil, err
	}
	return desired, nil
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
