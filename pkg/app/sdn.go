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

package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// OVSClient returns the OVS client, or nil if SDN is not configured.
func (app *App) OVSClient() ovs.ClientInterface {
	return app.ovsClient
}

// IPAMAllocator returns the IPAM allocator, or nil if IPAM is not configured.
func (app *App) IPAMAllocator() ipam.Allocator {
	return app.ipamAllocator
}

// initSDN initializes the SDN controller including the OVS client, IPAM
// allocator, and DHCP server based on the platform configuration. It is
// safe to call when SDN is not configured or disabled.
func (app *App) initSDN(ctx context.Context) error {
	if app.SDNConfig == nil || !app.SDNConfig.Enabled {
		return nil
	}

	if err := app.SDNConfig.Validate(); err != nil {
		return ErrSDNConfigValidation{Cause: err}
	}

	app.Logger.Info("Initializing SDN controller",
		slog.Bool("controller", app.SDNConfig.Controller))

	// Initialize the OVS client and create the bridge
	if app.SDNConfig.OVS != nil {
		if err := app.initOVSBridge(ctx); err != nil {
			return err
		}
	}

	// Initialize the IPAM allocator and create pools from config
	if app.SDNConfig.IPAM != nil && len(app.SDNConfig.IPAM.Pools) > 0 {
		if err := app.initIPAMPools(ctx); err != nil {
			return err
		}
	}

	// Log DHCP status for each pool
	app.logDHCPStatus()

	// Log overall SDN status
	app.logSDNStatus()

	return nil
}

// initOVSBridge creates the OVS client, connects to OVSDB, and ensures
// the configured bridge exists.
func (app *App) initOVSBridge(ctx context.Context) error {
	cfg := app.SDNConfig.OVS

	client, err := ovs.NewClient(cfg.Socket)
	if err != nil {
		return ErrSDNOVSClientInit{Cause: err}
	}

	if err := client.Connect(ctx); err != nil {
		return ErrSDNOVSConnect{
			Socket: cfg.Socket,
			Cause:  err,
		}
	}

	// Create the bridge if it does not already exist
	bridge, err := client.CreateBridge(ctx, cfg.Bridge)
	if err != nil {
		if !errors.Is(err, ovs.ErrBridgeExists) {
			return ErrSDNBridgeCreate{
				Bridge: cfg.Bridge,
				Cause:  err,
			}
		}
		// Bridge already exists -- fetch it for logging
		bridge, err = client.GetBridge(ctx, cfg.Bridge)
		if err != nil {
			return ErrSDNBridgeCreate{
				Bridge: cfg.Bridge,
				Cause:  err,
			}
		}
		app.Logger.Info("OVS bridge already exists",
			slog.String("bridge", cfg.Bridge),
			slog.String("uuid", bridge.UUID))
	} else {
		app.Logger.Info("Created OVS bridge",
			slog.String("bridge", cfg.Bridge),
			slog.String("uuid", bridge.UUID))
	}

	// Set bridge protocols if configured
	if len(cfg.Protocols) > 0 {
		if err := client.SetBridgeProtocols(ctx, cfg.Bridge, cfg.Protocols); err != nil {
			app.Logger.Warn("Failed to set bridge protocols",
				slog.String("bridge", cfg.Bridge),
				slog.String("error", err.Error()))
		}
	}

	app.ovsClient = client
	return nil
}

// initIPAMPools creates the IPAM allocator and registers all configured pools.
func (app *App) initIPAMPools(ctx context.Context) error {
	allocator := backends.NewMemoryBackend(
		ipam.WithLogger(app.Logger.Slog()),
	)

	for i := range app.SDNConfig.IPAM.Pools {
		poolCfg := &app.SDNConfig.IPAM.Pools[i]

		pool := &ipam.Pool{
			ID:                   poolCfg.Name,
			Name:                 poolCfg.Name,
			CIDR:                 poolCfg.CIDR,
			Gateway:              poolCfg.Gateway,
			DefaultLeaseDuration: poolCfg.LeaseDuration,
		}

		if err := allocator.CreatePool(ctx, pool); err != nil {
			return ErrSDNIPAMPoolCreate{
				Pool:  poolCfg.Name,
				Cause: err,
			}
		}

		app.Logger.Info("Created IPAM pool",
			slog.String("pool", poolCfg.Name),
			slog.String("cidr", poolCfg.CIDR.String()),
			slog.Bool("dhcp", poolCfg.DHCP))
	}

	app.ipamAllocator = allocator
	return nil
}

// logDHCPStatus logs which pools have DHCP enabled or disabled.
func (app *App) logDHCPStatus() {
	if app.SDNConfig.IPAM == nil {
		return
	}

	dhcpEnabled := false
	for _, pool := range app.SDNConfig.IPAM.Pools {
		if pool.DHCP {
			dhcpEnabled = true
			app.Logger.Info("DHCP enabled for pool",
				slog.String("pool", pool.Name),
				slog.String("cidr", pool.CIDR.String()))
		} else {
			app.Logger.Debug("DHCP disabled for pool",
				slog.String("pool", pool.Name))
		}
	}

	if app.SDNConfig.DHCP != nil && app.SDNConfig.DHCP.Enabled && dhcpEnabled {
		app.Logger.Info("DHCP server configured",
			slog.String("interface", app.SDNConfig.DHCP.Interface))
	}
}

// logSDNStatus logs the final SDN initialization status.
func (app *App) logSDNStatus() {
	mode := "agent"
	if app.SDNConfig.Controller {
		mode = "controller"
	}

	bridgeName := "<none>"
	if app.SDNConfig.OVS != nil {
		bridgeName = app.SDNConfig.OVS.Bridge
	}

	poolCount := 0
	dhcpPoolCount := 0
	if app.SDNConfig.IPAM != nil {
		poolCount = len(app.SDNConfig.IPAM.Pools)
		for _, p := range app.SDNConfig.IPAM.Pools {
			if p.DHCP {
				dhcpPoolCount++
			}
		}
	}

	app.Logger.Info("SDN initialized",
		slog.String("mode", mode),
		slog.String("bridge", bridgeName),
		slog.Int("pools", poolCount),
		slog.Int("dhcp_pools", dhcpPoolCount))
}
