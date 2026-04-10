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

package bridge

import (
	"context"
	"log/slog"
)

// LifecycleHooks provides callbacks for tenant lifecycle events
type LifecycleHooks struct {
	manager     *Manager
	flowManager *FlowManager
	logger      *slog.Logger
}

// NewLifecycleHooks creates new lifecycle hooks
func NewLifecycleHooks(manager *Manager, flowManager *FlowManager, logger *slog.Logger) *LifecycleHooks {
	if logger == nil {
		logger = slog.Default()
	}

	return &LifecycleHooks{
		manager:     manager,
		flowManager: flowManager,
		logger:      logger,
	}
}

// OnTenantCreate is called when a tenant is created
// Creates the OVS bridge and installs base flows
func (h *LifecycleHooks) OnTenantCreate(ctx context.Context, tenantID, tenantName string, vlanRange VLANRange) error {
	h.logger.Info("handling tenant create event",
		"tenant_id", tenantID,
		"tenant_name", tenantName,
		"vlan_range_start", vlanRange.Start,
		"vlan_range_end", vlanRange.End,
	)

	// Create the bridge
	bridge, err := h.manager.CreateBridge(ctx, tenantID, tenantName, vlanRange)
	if err != nil {
		h.logger.Error("failed to create bridge on tenant create",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Install base flows
	if h.flowManager != nil {
		if err := h.flowManager.InstallBaseFlows(ctx, bridge.Name, vlanRange); err != nil {
			h.logger.Error("failed to install base flows, rolling back bridge",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)

			// Rollback: delete the bridge
			if delErr := h.manager.DeleteBridge(ctx, tenantID); delErr != nil {
				h.logger.Error("failed to rollback bridge creation",
					"tenant_id", tenantID,
					"error", delErr,
				)
			}

			return err
		}

		// Install isolation flows
		if err := h.flowManager.InstallIsolationFlows(ctx, bridge.Name, vlanRange); err != nil {
			h.logger.Error("failed to install isolation flows",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)

			// Rollback: delete the bridge
			if delErr := h.manager.DeleteBridge(ctx, tenantID); delErr != nil {
				h.logger.Error("failed to rollback bridge creation",
					"tenant_id", tenantID,
					"error", delErr,
				)
			}

			return err
		}

		// Install ARP flows
		if err := h.flowManager.InstallARPFlows(ctx, bridge.Name, vlanRange); err != nil {
			h.logger.Warn("failed to install ARP flows, continuing",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			// ARP flows are not critical, don't rollback
		}

		// Install DHCP flows
		if err := h.flowManager.InstallDHCPFlows(ctx, bridge.Name, vlanRange); err != nil {
			h.logger.Warn("failed to install DHCP flows, continuing",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			// DHCP flows are not critical, don't rollback
		}
	}

	h.logger.Info("tenant create event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
	)

	return nil
}

// OnTenantActivate is called when a tenant becomes active
// Ensures flows are properly installed and bridge is operational
func (h *LifecycleHooks) OnTenantActivate(ctx context.Context, tenantID string) error {
	h.logger.Info("handling tenant activate event",
		"tenant_id", tenantID,
	)

	// Get the bridge
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get bridge on tenant activate",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Check current status
	if bridge.Status == StatusError {
		h.logger.Warn("bridge is in error state, attempting recovery",
			"tenant_id", tenantID,
			"bridge_name", bridge.Name,
			"error_message", bridge.ErrorMessage,
		)

		// Try to refresh bridge state
		if err := h.manager.Refresh(ctx, tenantID); err != nil {
			return err
		}
	}

	// Set status to active
	if err := h.manager.SetStatus(ctx, tenantID, StatusActive); err != nil {
		h.logger.Error("failed to set bridge status to active",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	h.logger.Info("tenant activate event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
	)

	return nil
}

// OnTenantSuspend is called when a tenant is suspended
// Installs drop flows to block all tenant traffic
func (h *LifecycleHooks) OnTenantSuspend(ctx context.Context, tenantID string) error {
	h.logger.Info("handling tenant suspend event",
		"tenant_id", tenantID,
	)

	// Get the bridge
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get bridge on tenant suspend",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Install drop-all flow at highest priority
	if h.flowManager != nil {
		dropFlow := &Flow{
			Table:    TableIngress,
			Priority: PriorityMax,
			Match:    FlowMatch{},
			Actions: []Action{
				{Type: ActionDrop},
			},
			Cookie: CookieSuspendFlow,
		}

		if err := h.flowManager.ofClient.AddFlow(ctx, bridge.Name, dropFlow); err != nil {
			h.logger.Error("failed to install suspend drop flow",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			return ErrFlowInstallFailed{Bridge: bridge.Name, Err: err}
		}
	}

	// Set status to suspended
	if err := h.manager.SetStatus(ctx, tenantID, StatusSuspended); err != nil {
		h.logger.Error("failed to set bridge status to suspended",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	h.logger.Info("tenant suspend event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
	)

	return nil
}

// OnTenantResume is called when a tenant is resumed
// Removes the drop flow installed during suspend
func (h *LifecycleHooks) OnTenantResume(ctx context.Context, tenantID string) error {
	h.logger.Info("handling tenant resume event",
		"tenant_id", tenantID,
	)

	// Get the bridge
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get bridge on tenant resume",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Remove the suspend drop flow by reinstalling base flows
	// This is safer than trying to delete specific flows
	if h.flowManager != nil {
		// Delete all flows
		if err := h.flowManager.DeleteAllFlows(ctx, bridge.Name); err != nil {
			h.logger.Error("failed to delete flows on resume",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			return err
		}

		// Reinstall base flows
		if err := h.flowManager.InstallBaseFlows(ctx, bridge.Name, bridge.VLANRange); err != nil {
			h.logger.Error("failed to reinstall base flows on resume",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			return err
		}

		// Reinstall isolation flows
		if err := h.flowManager.InstallIsolationFlows(ctx, bridge.Name, bridge.VLANRange); err != nil {
			h.logger.Error("failed to reinstall isolation flows on resume",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
			return err
		}

		// Reinstall ARP flows
		if err := h.flowManager.InstallARPFlows(ctx, bridge.Name, bridge.VLANRange); err != nil {
			h.logger.Warn("failed to reinstall ARP flows on resume",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
		}

		// Reinstall DHCP flows
		if err := h.flowManager.InstallDHCPFlows(ctx, bridge.Name, bridge.VLANRange); err != nil {
			h.logger.Warn("failed to reinstall DHCP flows on resume",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"error", err,
			)
		}
	}

	// Set status to active
	if err := h.manager.SetStatus(ctx, tenantID, StatusActive); err != nil {
		h.logger.Error("failed to set bridge status to active",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	h.logger.Info("tenant resume event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
	)

	return nil
}

// OnTenantDelete is called when a tenant is deleted
// Deletes the OVS bridge and all associated flows
func (h *LifecycleHooks) OnTenantDelete(ctx context.Context, tenantID string) error {
	h.logger.Info("handling tenant delete event",
		"tenant_id", tenantID,
	)

	// Get bridge name before deletion for logging
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	bridgeName := ""
	if err == nil && bridge != nil {
		bridgeName = bridge.Name
	}

	// Delete the bridge (this also deletes flows)
	if err := h.manager.DeleteBridge(ctx, tenantID); err != nil {
		h.logger.Error("failed to delete bridge on tenant delete",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	h.logger.Info("tenant delete event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridgeName,
	)

	return nil
}

// OnPortAdd is called when a port is added to a tenant bridge
func (h *LifecycleHooks) OnPortAdd(ctx context.Context, tenantID string, port uint32, vlan uint16) error {
	h.logger.Info("handling port add event",
		"tenant_id", tenantID,
		"port", port,
		"vlan", vlan,
	)

	// Get the bridge
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get bridge on port add",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Verify VLAN is within tenant range
	if !bridge.VLANRange.Contains(vlan) {
		h.logger.Error("VLAN not in tenant range",
			"tenant_id", tenantID,
			"vlan", vlan,
			"range_start", bridge.VLANRange.Start,
			"range_end", bridge.VLANRange.End,
		)
		return ErrInvalidVLANRange{
			Start:  vlan,
			End:    vlan,
			Reason: "VLAN not in tenant allocated range",
		}
	}

	// Install port flows
	if h.flowManager != nil {
		if err := h.flowManager.InstallPortFlows(ctx, bridge.Name, port, vlan); err != nil {
			h.logger.Error("failed to install port flows",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"port", port,
				"error", err,
			)
			return err
		}
	}

	// Refresh bridge info to update port count
	if err := h.manager.Refresh(ctx, tenantID); err != nil {
		h.logger.Warn("failed to refresh bridge info after port add",
			"tenant_id", tenantID,
			"error", err,
		)
	}

	h.logger.Info("port add event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
		"port", port,
		"vlan", vlan,
	)

	return nil
}

// OnPortRemove is called when a port is removed from a tenant bridge
func (h *LifecycleHooks) OnPortRemove(ctx context.Context, tenantID string, port uint32) error {
	h.logger.Info("handling port remove event",
		"tenant_id", tenantID,
		"port", port,
	)

	// Get the bridge
	bridge, err := h.manager.GetBridge(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get bridge on port remove",
			"tenant_id", tenantID,
			"error", err,
		)
		return err
	}

	// Delete port flows
	if h.flowManager != nil {
		if err := h.flowManager.DeletePortFlows(ctx, bridge.Name, port); err != nil {
			h.logger.Error("failed to delete port flows",
				"tenant_id", tenantID,
				"bridge_name", bridge.Name,
				"port", port,
				"error", err,
			)
			return err
		}
	}

	// Refresh bridge info to update port count
	if err := h.manager.Refresh(ctx, tenantID); err != nil {
		h.logger.Warn("failed to refresh bridge info after port remove",
			"tenant_id", tenantID,
			"error", err,
		)
	}

	h.logger.Info("port remove event handled successfully",
		"tenant_id", tenantID,
		"bridge_name", bridge.Name,
		"port", port,
	)

	return nil
}
