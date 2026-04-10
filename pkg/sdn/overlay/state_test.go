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

package overlay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestStateManager_VTEPOperations(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	t.Run("add VTEP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID:  "node1",
			IP:      netip.MustParseAddr("10.0.0.1"),
			Healthy: true,
		}

		if err := sm.AddVTEP(ctx, vtep); err != nil {
			t.Errorf("AddVTEP() error = %v", err)
		}
	})

	t.Run("get VTEP", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		vtep, err := sm.GetVTEP(ctx, ip)
		if err != nil {
			t.Errorf("GetVTEP() error = %v", err)
		}
		if vtep.NodeID != "node1" {
			t.Errorf("NodeID = %s, want node1", vtep.NodeID)
		}
	})

	t.Run("add duplicate VTEP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID:  "node1-duplicate",
			IP:      netip.MustParseAddr("10.0.0.1"),
			Healthy: true,
		}

		err := sm.AddVTEP(ctx, vtep)
		if err != ErrVTEPAlreadyExists {
			t.Errorf("AddVTEP() duplicate = %v, want %v", err, ErrVTEPAlreadyExists)
		}
	})

	t.Run("update VTEP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID:  "node1",
			IP:      netip.MustParseAddr("10.0.0.1"),
			Healthy: false,
		}

		if err := sm.UpdateVTEP(ctx, vtep); err != nil {
			t.Errorf("UpdateVTEP() error = %v", err)
		}

		updated, _ := sm.GetVTEP(ctx, vtep.IP)
		if updated.Healthy {
			t.Errorf("Healthy after update = true, want false")
		}
	})

	t.Run("update nonexistent VTEP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID: "node99",
			IP:     netip.MustParseAddr("10.0.0.99"),
		}

		err := sm.UpdateVTEP(ctx, vtep)
		if err != ErrVTEPNotFound {
			t.Errorf("UpdateVTEP() nonexistent = %v, want %v", err, ErrVTEPNotFound)
		}
	})

	t.Run("list VTEPs", func(t *testing.T) {
		// Add another VTEP
		vtep2 := &VTEPInfo{
			NodeID:  "node2",
			IP:      netip.MustParseAddr("10.0.0.2"),
			Healthy: true,
		}
		sm.AddVTEP(ctx, vtep2)

		vteps, err := sm.ListVTEPs(ctx)
		if err != nil {
			t.Errorf("ListVTEPs() error = %v", err)
		}
		if len(vteps) != 2 {
			t.Errorf("len(VTEPs) = %d, want 2", len(vteps))
		}
	})

	t.Run("remove VTEP", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		if err := sm.RemoveVTEP(ctx, ip); err != nil {
			t.Errorf("RemoveVTEP() error = %v", err)
		}

		_, err := sm.GetVTEP(ctx, ip)
		if err != ErrVTEPNotFound {
			t.Errorf("GetVTEP() after remove = %v, want %v", err, ErrVTEPNotFound)
		}
	})

	t.Run("remove nonexistent VTEP", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.99")
		err := sm.RemoveVTEP(ctx, ip)
		if err != ErrVTEPNotFound {
			t.Errorf("RemoveVTEP() nonexistent = %v, want %v", err, ErrVTEPNotFound)
		}
	})

	t.Run("add nil VTEP", func(t *testing.T) {
		err := sm.AddVTEP(ctx, nil)
		if err != ErrVTEPNotFound {
			t.Errorf("AddVTEP(nil) = %v, want %v", err, ErrVTEPNotFound)
		}
	})

	t.Run("add VTEP with invalid IP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID: "invalid",
			IP:     netip.Addr{},
		}
		err := sm.AddVTEP(ctx, vtep)
		if _, ok := err.(*ErrInvalidIP); !ok {
			t.Errorf("AddVTEP() invalid IP error = %T, want *ErrInvalidIP", err)
		}
	})

	t.Run("update nil VTEP", func(t *testing.T) {
		err := sm.UpdateVTEP(ctx, nil)
		if err != ErrVTEPNotFound {
			t.Errorf("UpdateVTEP(nil) = %v, want %v", err, ErrVTEPNotFound)
		}
	})
}

func TestStateManager_TunnelOperations(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	localVTEP := netip.MustParseAddr("10.0.0.1")
	remoteVTEP := netip.MustParseAddr("10.0.0.2")
	vni := uint32(100000)

	t.Run("add tunnel", func(t *testing.T) {
		tunnel := &TunnelInfo{
			ID:         "tunnel-1",
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        vni,
			OVSPort:    "vxlan0",
		}

		if err := sm.AddTunnel(ctx, tunnel); err != nil {
			t.Errorf("AddTunnel() error = %v", err)
		}
	})

	t.Run("get tunnel", func(t *testing.T) {
		tunnel, err := sm.GetTunnel(ctx, localVTEP, remoteVTEP, vni)
		if err != nil {
			t.Errorf("GetTunnel() error = %v", err)
		}
		if tunnel.ID != "tunnel-1" {
			t.Errorf("ID = %s, want tunnel-1", tunnel.ID)
		}
	})

	t.Run("add duplicate tunnel", func(t *testing.T) {
		tunnel := &TunnelInfo{
			ID:         "tunnel-1-dup",
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        vni,
		}

		err := sm.AddTunnel(ctx, tunnel)
		if err != ErrTunnelAlreadyExists {
			t.Errorf("AddTunnel() duplicate = %v, want %v", err, ErrTunnelAlreadyExists)
		}
	})

	t.Run("update tunnel", func(t *testing.T) {
		tunnel := &TunnelInfo{
			ID:         "tunnel-1",
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        vni,
			OVSPort:    "vxlan0-updated",
		}

		if err := sm.UpdateTunnel(ctx, tunnel); err != nil {
			t.Errorf("UpdateTunnel() error = %v", err)
		}

		updated, _ := sm.GetTunnel(ctx, localVTEP, remoteVTEP, vni)
		if updated.OVSPort != "vxlan0-updated" {
			t.Errorf("OVSPort = %s, want vxlan0-updated", updated.OVSPort)
		}
	})

	t.Run("update nonexistent tunnel", func(t *testing.T) {
		tunnel := &TunnelInfo{
			ID:         "tunnel-nonexistent",
			LocalVTEP:  localVTEP,
			RemoteVTEP: netip.MustParseAddr("10.0.0.99"),
			VNI:        vni,
		}

		err := sm.UpdateTunnel(ctx, tunnel)
		if err != ErrTunnelNotFound {
			t.Errorf("UpdateTunnel() nonexistent = %v, want %v", err, ErrTunnelNotFound)
		}
	})

	t.Run("update nil tunnel", func(t *testing.T) {
		err := sm.UpdateTunnel(ctx, nil)
		if err != ErrTunnelNotFound {
			t.Errorf("UpdateTunnel(nil) = %v, want %v", err, ErrTunnelNotFound)
		}
	})

	t.Run("list tunnels", func(t *testing.T) {
		// Add another tunnel
		tunnel2 := &TunnelInfo{
			ID:         "tunnel-2",
			LocalVTEP:  localVTEP,
			RemoteVTEP: netip.MustParseAddr("10.0.0.3"),
			VNI:        vni,
		}
		sm.AddTunnel(ctx, tunnel2)

		tunnels, err := sm.ListTunnels(ctx)
		if err != nil {
			t.Errorf("ListTunnels() error = %v", err)
		}
		if len(tunnels) != 2 {
			t.Errorf("len(tunnels) = %d, want 2", len(tunnels))
		}
	})

	t.Run("list tunnels by VNI", func(t *testing.T) {
		// Add tunnel with different VNI
		tunnel3 := &TunnelInfo{
			ID:         "tunnel-3",
			LocalVTEP:  localVTEP,
			RemoteVTEP: netip.MustParseAddr("10.0.0.4"),
			VNI:        200000,
		}
		sm.AddTunnel(ctx, tunnel3)

		tunnels, err := sm.ListTunnelsByVNI(ctx, vni)
		if err != nil {
			t.Errorf("ListTunnelsByVNI() error = %v", err)
		}
		if len(tunnels) != 2 {
			t.Errorf("len(tunnels) for VNI %d = %d, want 2", vni, len(tunnels))
		}
	})

	t.Run("remove tunnel", func(t *testing.T) {
		if err := sm.RemoveTunnel(ctx, localVTEP, remoteVTEP, vni); err != nil {
			t.Errorf("RemoveTunnel() error = %v", err)
		}

		_, err := sm.GetTunnel(ctx, localVTEP, remoteVTEP, vni)
		if err != ErrTunnelNotFound {
			t.Errorf("GetTunnel() after remove = %v, want %v", err, ErrTunnelNotFound)
		}
	})

	t.Run("remove nonexistent tunnel", func(t *testing.T) {
		err := sm.RemoveTunnel(ctx, localVTEP, remoteVTEP, 999999)
		if err != ErrTunnelNotFound {
			t.Errorf("RemoveTunnel() nonexistent = %v, want %v", err, ErrTunnelNotFound)
		}
	})

	t.Run("add nil tunnel", func(t *testing.T) {
		err := sm.AddTunnel(ctx, nil)
		if err != ErrTunnelNotFound {
			t.Errorf("AddTunnel(nil) = %v, want %v", err, ErrTunnelNotFound)
		}
	})
}

func TestStateManager_VNIOperations(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	t.Run("add VNI", func(t *testing.T) {
		vni := &VNIInfo{
			VNI:  100000,
			VLAN: 100,
		}

		if err := sm.AddVNI(ctx, vni); err != nil {
			t.Errorf("AddVNI() error = %v", err)
		}
	})

	t.Run("get VNI", func(t *testing.T) {
		vni, err := sm.GetVNI(ctx, 100000)
		if err != nil {
			t.Errorf("GetVNI() error = %v", err)
		}
		if vni.VLAN != 100 {
			t.Errorf("VLAN = %d, want 100", vni.VLAN)
		}
	})

	t.Run("add duplicate VNI", func(t *testing.T) {
		vni := &VNIInfo{
			VNI:  100000,
			VLAN: 200,
		}

		err := sm.AddVNI(ctx, vni)
		if err != ErrVNIAlreadyExists {
			t.Errorf("AddVNI() duplicate = %v, want %v", err, ErrVNIAlreadyExists)
		}
	})

	t.Run("update VNI", func(t *testing.T) {
		vni := &VNIInfo{
			VNI:      100000,
			VLAN:     150,
			MACCount: 5,
		}

		if err := sm.UpdateVNI(ctx, vni); err != nil {
			t.Errorf("UpdateVNI() error = %v", err)
		}

		updated, _ := sm.GetVNI(ctx, 100000)
		if updated.VLAN != 150 {
			t.Errorf("VLAN after update = %d, want 150", updated.VLAN)
		}
	})

	t.Run("update nonexistent VNI", func(t *testing.T) {
		vni := &VNIInfo{
			VNI:  999999,
			VLAN: 100,
		}

		err := sm.UpdateVNI(ctx, vni)
		if err != ErrVNINotFound {
			t.Errorf("UpdateVNI() nonexistent = %v, want %v", err, ErrVNINotFound)
		}
	})

	t.Run("update nil VNI", func(t *testing.T) {
		err := sm.UpdateVNI(ctx, nil)
		if err != ErrVNINotFound {
			t.Errorf("UpdateVNI(nil) = %v, want %v", err, ErrVNINotFound)
		}
	})

	t.Run("list VNIs", func(t *testing.T) {
		vni2 := &VNIInfo{
			VNI:  200000,
			VLAN: 200,
		}
		sm.AddVNI(ctx, vni2)

		vnis, err := sm.ListVNIs(ctx)
		if err != nil {
			t.Errorf("ListVNIs() error = %v", err)
		}
		if len(vnis) != 2 {
			t.Errorf("len(VNIs) = %d, want 2", len(vnis))
		}
	})

	t.Run("remove VNI", func(t *testing.T) {
		if err := sm.RemoveVNI(ctx, 100000); err != nil {
			t.Errorf("RemoveVNI() error = %v", err)
		}

		_, err := sm.GetVNI(ctx, 100000)
		if err != ErrVNINotFound {
			t.Errorf("GetVNI() after remove = %v, want %v", err, ErrVNINotFound)
		}
	})

	t.Run("remove nonexistent VNI", func(t *testing.T) {
		err := sm.RemoveVNI(ctx, 999999)
		if err != ErrVNINotFound {
			t.Errorf("RemoveVNI() nonexistent = %v, want %v", err, ErrVNINotFound)
		}
	})

	t.Run("add nil VNI", func(t *testing.T) {
		err := sm.AddVNI(ctx, nil)
		if err != ErrVNINotFound {
			t.Errorf("AddVNI(nil) = %v, want %v", err, ErrVNINotFound)
		}
	})
}

func TestStateManager_RemoteMACOperations(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	// Setup: Add a VNI first
	vni := &VNIInfo{VNI: 100000}
	sm.AddVNI(ctx, vni)

	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	remoteVTEP := netip.MustParseAddr("10.0.0.2")

	t.Run("add remote MAC", func(t *testing.T) {
		entry := &RemoteMACEntry{
			MAC:        testMAC,
			VNI:        100000,
			RemoteVTEP: remoteVTEP,
			LearnedAt:  time.Now(),
			Source:     "evpn",
		}

		if err := sm.AddRemoteMAC(ctx, entry); err != nil {
			t.Errorf("AddRemoteMAC() error = %v", err)
		}
	})

	t.Run("get remote MAC", func(t *testing.T) {
		entry, err := sm.GetRemoteMAC(ctx, 100000, testMAC)
		if err != nil {
			t.Errorf("GetRemoteMAC() error = %v", err)
		}
		if entry.RemoteVTEP != remoteVTEP {
			t.Errorf("RemoteVTEP = %v, want %v", entry.RemoteVTEP, remoteVTEP)
		}
	})

	t.Run("add duplicate MAC", func(t *testing.T) {
		entry := &RemoteMACEntry{
			MAC:        testMAC,
			VNI:        100000,
			RemoteVTEP: netip.MustParseAddr("10.0.0.3"),
		}

		err := sm.AddRemoteMAC(ctx, entry)
		if err != ErrMACAlreadyExists {
			t.Errorf("AddRemoteMAC() duplicate = %v, want %v", err, ErrMACAlreadyExists)
		}
	})

	t.Run("update remote MAC", func(t *testing.T) {
		newVTEP := netip.MustParseAddr("10.0.0.3")
		entry := &RemoteMACEntry{
			MAC:        testMAC,
			VNI:        100000,
			RemoteVTEP: newVTEP,
			LearnedAt:  time.Now(),
			Source:     "datapath",
		}

		if err := sm.UpdateRemoteMAC(ctx, entry); err != nil {
			t.Errorf("UpdateRemoteMAC() error = %v", err)
		}

		updated, _ := sm.GetRemoteMAC(ctx, 100000, testMAC)
		if updated.RemoteVTEP != newVTEP {
			t.Errorf("RemoteVTEP after update = %v, want %v", updated.RemoteVTEP, newVTEP)
		}
	})

	t.Run("update nonexistent MAC", func(t *testing.T) {
		nonexistentMAC, _ := net.ParseMAC("00:11:22:33:44:99")
		entry := &RemoteMACEntry{
			MAC:        nonexistentMAC,
			VNI:        100000,
			RemoteVTEP: remoteVTEP,
		}

		err := sm.UpdateRemoteMAC(ctx, entry)
		if err != ErrMACNotFound {
			t.Errorf("UpdateRemoteMAC() nonexistent = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("update nil MAC", func(t *testing.T) {
		err := sm.UpdateRemoteMAC(ctx, nil)
		if err != ErrMACNotFound {
			t.Errorf("UpdateRemoteMAC(nil) = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("list MACs by VNI", func(t *testing.T) {
		// Add another MAC
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		entry2 := &RemoteMACEntry{
			MAC:        mac2,
			VNI:        100000,
			RemoteVTEP: remoteVTEP,
		}
		sm.AddRemoteMAC(ctx, entry2)

		macs, err := sm.ListRemoteMACsByVNI(ctx, 100000)
		if err != nil {
			t.Errorf("ListRemoteMACsByVNI() error = %v", err)
		}
		if len(macs) != 2 {
			t.Errorf("len(MACs) = %d, want 2", len(macs))
		}
	})

	t.Run("list MACs by nonexistent VNI", func(t *testing.T) {
		macs, err := sm.ListRemoteMACsByVNI(ctx, 999999)
		if err != nil {
			t.Errorf("ListRemoteMACsByVNI() error = %v", err)
		}
		if len(macs) != 0 {
			t.Errorf("len(MACs) for nonexistent VNI = %d, want 0", len(macs))
		}
	})

	t.Run("list all MACs", func(t *testing.T) {
		// Add MAC for different VNI
		vni2 := &VNIInfo{VNI: 200000}
		sm.AddVNI(ctx, vni2)

		mac3, _ := net.ParseMAC("00:11:22:33:44:77")
		entry3 := &RemoteMACEntry{
			MAC:        mac3,
			VNI:        200000,
			RemoteVTEP: remoteVTEP,
		}
		sm.AddRemoteMAC(ctx, entry3)

		macs, err := sm.ListAllRemoteMACs(ctx)
		if err != nil {
			t.Errorf("ListAllRemoteMACs() error = %v", err)
		}
		if len(macs) != 3 {
			t.Errorf("len(all MACs) = %d, want 3", len(macs))
		}
	})

	t.Run("remove MAC", func(t *testing.T) {
		if err := sm.RemoveRemoteMAC(ctx, 100000, testMAC); err != nil {
			t.Errorf("RemoveRemoteMAC() error = %v", err)
		}

		_, err := sm.GetRemoteMAC(ctx, 100000, testMAC)
		if err != ErrMACNotFound {
			t.Errorf("GetRemoteMAC() after remove = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("remove nonexistent MAC", func(t *testing.T) {
		err := sm.RemoveRemoteMAC(ctx, 100000, testMAC)
		if err != ErrMACNotFound {
			t.Errorf("RemoveRemoteMAC() nonexistent = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("add nil MAC entry", func(t *testing.T) {
		err := sm.AddRemoteMAC(ctx, nil)
		if err != ErrMACNotFound {
			t.Errorf("AddRemoteMAC(nil) = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("add MAC with nil MAC address", func(t *testing.T) {
		entry := &RemoteMACEntry{
			MAC: nil,
			VNI: 100000,
		}
		err := sm.AddRemoteMAC(ctx, entry)
		if _, ok := err.(*ErrInvalidMAC); !ok {
			t.Errorf("AddRemoteMAC() nil MAC = %T, want *ErrInvalidMAC", err)
		}
	})

	t.Run("remove VNI removes associated MACs", func(t *testing.T) {
		// Add a new VNI and MAC
		vni3 := &VNIInfo{VNI: 300000}
		sm.AddVNI(ctx, vni3)

		mac4, _ := net.ParseMAC("00:11:22:33:44:88")
		entry4 := &RemoteMACEntry{
			MAC:        mac4,
			VNI:        300000,
			RemoteVTEP: remoteVTEP,
		}
		sm.AddRemoteMAC(ctx, entry4)

		// Remove VNI
		sm.RemoveVNI(ctx, 300000)

		// MAC should be gone
		_, err := sm.GetRemoteMAC(ctx, 300000, mac4)
		if err != ErrMACNotFound {
			t.Errorf("GetRemoteMAC() after VNI remove = %v, want %v", err, ErrMACNotFound)
		}
	})
}

func TestStateManager_AddRemoteMACWithoutVNIIndex(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	// Add a MAC without the VNI index existing
	// This tests the branch that creates the macByVNI entry
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACEntry{
		MAC:        mac,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
		LearnedAt:  time.Now(),
		Source:     "test",
	}

	// Add the MAC - this will create the VNI index entry
	if err := sm.AddRemoteMAC(ctx, entry); err != nil {
		t.Errorf("AddRemoteMAC() error = %v", err)
	}

	// Verify it was added
	retrieved, err := sm.GetRemoteMAC(ctx, 100000, mac)
	if err != nil {
		t.Errorf("GetRemoteMAC() error = %v", err)
	}
	if retrieved.Source != "test" {
		t.Errorf("Source = %s, want test", retrieved.Source)
	}
}

func TestStateManager_MACExpiration(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	vni := &VNIInfo{VNI: 100000}
	sm.AddVNI(ctx, vni)

	// Add expired MAC
	expiredMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	expiredEntry := &RemoteMACEntry{
		MAC:        expiredMAC,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
		LearnedAt:  time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Minute), // Already expired
	}
	sm.AddRemoteMAC(ctx, expiredEntry)

	// Add non-expired MAC
	validMAC, _ := net.ParseMAC("00:11:22:33:44:66")
	validEntry := &RemoteMACEntry{
		MAC:        validMAC,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.3"),
		LearnedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour), // Not expired
	}
	sm.AddRemoteMAC(ctx, validEntry)

	// Expire MACs
	expired, err := sm.ExpireMACs(ctx)
	if err != nil {
		t.Errorf("ExpireMACs() error = %v", err)
	}

	if len(expired) != 1 {
		t.Errorf("len(expired) = %d, want 1", len(expired))
	}

	// Verify expired MAC is gone
	_, err = sm.GetRemoteMAC(ctx, 100000, expiredMAC)
	if err != ErrMACNotFound {
		t.Errorf("GetRemoteMAC() expired = %v, want %v", err, ErrMACNotFound)
	}

	// Verify valid MAC still exists
	_, err = sm.GetRemoteMAC(ctx, 100000, validMAC)
	if err != nil {
		t.Errorf("GetRemoteMAC() valid = %v", err)
	}
}

func TestStateManager_MACExpirationWithZeroExpiry(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	vni := &VNIInfo{VNI: 100000}
	sm.AddVNI(ctx, vni)

	// Add MAC with zero expiry (never expires)
	neverExpiresMAC, _ := net.ParseMAC("00:11:22:33:44:77")
	neverExpiresEntry := &RemoteMACEntry{
		MAC:        neverExpiresMAC,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.4"),
		LearnedAt:  time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Time{}, // Zero time - never expires
	}
	sm.AddRemoteMAC(ctx, neverExpiresEntry)

	// Expire MACs
	expired, err := sm.ExpireMACs(ctx)
	if err != nil {
		t.Errorf("ExpireMACs() error = %v", err)
	}

	if len(expired) != 0 {
		t.Errorf("len(expired) = %d, want 0 (zero expiry MAC should not expire)", len(expired))
	}

	// Verify MAC still exists
	_, err = sm.GetRemoteMAC(ctx, 100000, neverExpiresMAC)
	if err != nil {
		t.Errorf("GetRemoteMAC() zero expiry = %v", err)
	}
}

func TestStateManager_GetStats(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	// Add some data
	sm.AddVTEP(ctx, &VTEPInfo{NodeID: "node1", IP: netip.MustParseAddr("10.0.0.1")})
	sm.AddVTEP(ctx, &VTEPInfo{NodeID: "node2", IP: netip.MustParseAddr("10.0.0.2")})

	sm.AddVNI(ctx, &VNIInfo{VNI: 100000})

	sm.AddTunnel(ctx, &TunnelInfo{
		LocalVTEP:  netip.MustParseAddr("10.0.0.1"),
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
		VNI:        100000,
	})

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	sm.AddRemoteMAC(ctx, &RemoteMACEntry{
		MAC:        mac,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
	})

	stats := sm.GetStats(ctx)

	if stats.VTEPCount != 2 {
		t.Errorf("VTEPCount = %d, want 2", stats.VTEPCount)
	}
	if stats.VNICount != 1 {
		t.Errorf("VNICount = %d, want 1", stats.VNICount)
	}
	if stats.TunnelCount != 1 {
		t.Errorf("TunnelCount = %d, want 1", stats.TunnelCount)
	}
	if stats.RemoteMACCount != 1 {
		t.Errorf("RemoteMACCount = %d, want 1", stats.RemoteMACCount)
	}
}

func TestStateManager_Clear(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	// Add some data
	sm.AddVTEP(ctx, &VTEPInfo{NodeID: "node1", IP: netip.MustParseAddr("10.0.0.1")})
	sm.AddVNI(ctx, &VNIInfo{VNI: 100000})
	sm.AddTunnel(ctx, &TunnelInfo{
		LocalVTEP:  netip.MustParseAddr("10.0.0.1"),
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
		VNI:        100000,
	})

	// Clear
	if err := sm.Clear(ctx); err != nil {
		t.Errorf("Clear() error = %v", err)
	}

	// Verify all data is gone
	stats := sm.GetStats(ctx)
	if stats.VTEPCount != 0 {
		t.Errorf("VTEPCount after clear = %d, want 0", stats.VTEPCount)
	}
	if stats.VNICount != 0 {
		t.Errorf("VNICount after clear = %d, want 0", stats.VNICount)
	}
	if stats.TunnelCount != 0 {
		t.Errorf("TunnelCount after clear = %d, want 0", stats.TunnelCount)
	}
}

func TestStateManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	sm := NewStateManager()
	ctx := context.Background()

	// Setup
	sm.AddVNI(ctx, &VNIInfo{VNI: 100000})

	done := make(chan struct{})

	// Concurrent writes
	go func() {
		for i := 0; i < 100; i++ {
			mac := make(net.HardwareAddr, 6)
			mac[5] = byte(i)
			sm.AddRemoteMAC(ctx, &RemoteMACEntry{
				MAC:        mac,
				VNI:        100000,
				RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			})
		}
		done <- struct{}{}
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			sm.ListRemoteMACsByVNI(ctx, 100000)
		}
		done <- struct{}{}
	}()

	// Wait for both
	<-done
	<-done

	// Verify state is consistent
	macs, err := sm.ListRemoteMACsByVNI(ctx, 100000)
	if err != nil {
		t.Errorf("ListRemoteMACsByVNI() after concurrent access error = %v", err)
	}

	if len(macs) != 100 {
		t.Errorf("len(MACs) after concurrent access = %d, want 100", len(macs))
	}
}
