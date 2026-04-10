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

package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBridgeDAO_List_CorruptData verifies that corrupt data in storage
// is skipped with a warning rather than causing the entire list to fail.
func TestBridgeDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger, WithBridgeRequestTimeout(5*time.Second))

	mock.SetData("SDNBridge", 1, []byte("not-json"))

	ctx := context.Background()
	bridges, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, bridges)
}

// TestBridgeDAO_ListByNode_CorruptData verifies corrupt entries are skipped
// when listing bridges by node.
func TestBridgeDAO_ListByNode_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger, WithBridgeRequestTimeout(5*time.Second))

	mock.SetData("SDNBridge", 1, []byte("corrupt"))

	ctx := context.Background()
	bridges, err := dao.ListByNode(ctx, 42)
	require.NoError(t, err)
	assert.Empty(t, bridges)
}

// TestBridgeDAO_ListByNode_NoMatch verifies filtering works correctly.
func TestBridgeDAO_ListByNode_NoMatch(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:     "br-1",
		Name:   "bridge1",
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, bridge))

	bridges, err := dao.ListByNode(ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, bridges)
}

// TestFlowDAO_List_CorruptData verifies that corrupt flow data is skipped.
func TestFlowDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	mock.SetData("SDNFlow", 1, []byte("invalid-json"))

	ctx := context.Background()
	flows, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, flows)
}

// TestFlowDAO_ListByBridge_CorruptData verifies corrupt entries are skipped.
func TestFlowDAO_ListByBridge_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	mock.SetData("SDNFlow", 1, []byte("bad"))

	ctx := context.Background()
	flows, err := dao.ListByBridge(ctx, "br-1")
	require.NoError(t, err)
	assert.Empty(t, flows)
}

// TestFlowDAO_ListByBridgeAndTable_CorruptData verifies corrupt entries are skipped.
func TestFlowDAO_ListByBridgeAndTable_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	mock.SetData("SDNFlow", 1, []byte("bad"))

	ctx := context.Background()
	flows, err := dao.ListByBridgeAndTable(ctx, "br-1", 0)
	require.NoError(t, err)
	assert.Empty(t, flows)
}

// TestPortDAO_List_CorruptData verifies corrupt port data is skipped.
func TestPortDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	mock.SetData("SDNPort", 1, []byte("bad"))

	ctx := context.Background()
	ports, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, ports)
}

// TestPortDAO_ListByBridge_CorruptData verifies corrupt entries are skipped.
func TestPortDAO_ListByBridge_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	mock.SetData("SDNPort", 1, []byte("bad"))

	ctx := context.Background()
	ports, err := dao.ListByBridge(ctx, "br-1")
	require.NoError(t, err)
	assert.Empty(t, ports)
}

// TestPortDAO_ListByNode_CorruptData verifies corrupt entries are skipped.
func TestPortDAO_ListByNode_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	mock.SetData("SDNPort", 1, []byte("bad"))

	ctx := context.Background()
	ports, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, ports)
}

// TestRemoteMACDAO_List_CorruptData verifies corrupt entries are skipped.
func TestRemoteMACDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.SetData("SDNRemoteMAC", 1, []byte("bad"))

	ctx := context.Background()
	macs, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, macs)
}

// TestRemoteMACDAO_ListByVNI_CorruptData verifies corrupt entries are skipped.
func TestRemoteMACDAO_ListByVNI_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.SetData("SDNRemoteMAC", 1, []byte("bad"))

	ctx := context.Background()
	macs, err := dao.ListByVNI(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, macs)
}

// TestRemoteMACDAO_ListByVTEP_CorruptData verifies corrupt entries are skipped.
func TestRemoteMACDAO_ListByVTEP_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.SetData("SDNRemoteMAC", 1, []byte("bad"))

	ctx := context.Background()
	macs, err := dao.ListByVTEP(ctx, "vtep-1")
	require.NoError(t, err)
	assert.Empty(t, macs)
}

// TestRemoteMACDAO_ListByNode_CorruptData verifies corrupt entries are skipped.
func TestRemoteMACDAO_ListByNode_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.SetData("SDNRemoteMAC", 1, []byte("bad"))

	ctx := context.Background()
	macs, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, macs)
}

// TestTunnelDAO_List_CorruptData verifies corrupt tunnel data is skipped.
func TestTunnelDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.SetData("SDNTunnel", 1, []byte("bad"))

	ctx := context.Background()
	tunnels, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

// TestTunnelDAO_ListByVTEP_CorruptData verifies corrupt entries are skipped.
func TestTunnelDAO_ListByVTEP_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.SetData("SDNTunnel", 1, []byte("bad"))

	ctx := context.Background()
	tunnels, err := dao.ListByVTEP(ctx, "vtep-1")
	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

// TestTunnelDAO_ListByVNI_CorruptData verifies corrupt entries are skipped.
func TestTunnelDAO_ListByVNI_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.SetData("SDNTunnel", 1, []byte("bad"))

	ctx := context.Background()
	tunnels, err := dao.ListByVNI(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

// TestTunnelDAO_ListByNode_CorruptData verifies corrupt entries are skipped.
func TestTunnelDAO_ListByNode_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.SetData("SDNTunnel", 1, []byte("bad"))

	ctx := context.Background()
	tunnels, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

// TestTunnelDAO_ListByVTEP_ListStorageError verifies storage errors are propagated.
func TestTunnelDAO_ListByVTEP_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByVTEP(ctx, "vtep-1")
	require.Error(t, err)
}

// TestTunnelDAO_ListByVNI_ListStorageError verifies storage errors are propagated.
func TestTunnelDAO_ListByVNI_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByVNI(ctx, 100)
	require.Error(t, err)
}

// TestTunnelDAO_ListByNode_ListStorageError verifies storage errors are propagated.
func TestTunnelDAO_ListByNode_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByNode(ctx, 1)
	require.Error(t, err)
}

// TestVLANDAO_List_CorruptData verifies corrupt VLAN data is skipped.
func TestVLANDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger, WithVLANRequestTimeout(5*time.Second))

	mock.SetData("SDNVLAN", 1, []byte("bad"))

	ctx := context.Background()
	vlans, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, vlans)
}

// TestVLANDAO_ListByPort_CorruptData verifies corrupt entries are skipped.
func TestVLANDAO_ListByPort_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger, WithVLANRequestTimeout(5*time.Second))

	mock.SetData("SDNVLAN", 1, []byte("bad"))

	ctx := context.Background()
	vlans, err := dao.ListByPort(ctx, "port-1")
	require.NoError(t, err)
	assert.Empty(t, vlans)
}

// TestVNIMappingDAO_List_CorruptData verifies corrupt data is skipped.
func TestVNIMappingDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	mock.SetData("SDNVNIMapping", 1, []byte("bad"))

	ctx := context.Background()
	mappings, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, mappings)
}

// TestVNIMappingDAO_GetByBridge_CorruptData verifies corrupt entries are skipped.
func TestVNIMappingDAO_GetByBridge_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	mock.SetData("SDNVNIMapping", 1, []byte("bad"))

	ctx := context.Background()
	mappings, err := dao.GetByBridge(ctx, "br-1")
	require.NoError(t, err)
	assert.Empty(t, mappings)
}

// TestVNIMappingDAO_ListByTenant_CorruptData verifies corrupt entries are skipped.
func TestVNIMappingDAO_ListByTenant_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	mock.SetData("SDNVNIMapping", 1, []byte("bad"))

	ctx := context.Background()
	mappings, err := dao.ListByTenant(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Empty(t, mappings)
}

// TestVNIMappingDAO_GetByBridge_ListStorageError verifies storage errors are propagated.
func TestVNIMappingDAO_GetByBridge_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.GetByBridge(ctx, "br-1")
	require.Error(t, err)
}

// TestVNIMappingDAO_ListByTenant_ListStorageError verifies storage errors are propagated.
func TestVNIMappingDAO_ListByTenant_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByTenant(ctx, "tenant-1")
	require.Error(t, err)
}

// TestVTEPDAO_List_CorruptData verifies corrupt data is skipped.
func TestVTEPDAO_List_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVTEPDAO(mock, logger, WithVTEPRequestTimeout(5*time.Second))

	mock.SetData("SDNVTEP", 1, []byte("bad"))

	ctx := context.Background()
	vteps, err := dao.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, vteps)
}

// TestVTEPDAO_ListByNode_CorruptData verifies corrupt entries are skipped.
func TestVTEPDAO_ListByNode_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVTEPDAO(mock, logger, WithVTEPRequestTimeout(5*time.Second))

	mock.SetData("SDNVTEP", 1, []byte("bad"))

	ctx := context.Background()
	vteps, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, vteps)
}

// TestVTEPDAO_ListByNode_ListStorageError verifies storage errors are propagated.
func TestVTEPDAO_ListByNode_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVTEPDAO(mock, logger, WithVTEPRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByNode(ctx, 1)
	require.Error(t, err)
}

// TestRemoteMACDAO_DeleteExpired_CorruptData verifies corrupt entries are skipped
// during delete expired operation.
func TestRemoteMACDAO_DeleteExpired_CorruptData(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.SetData("SDNRemoteMAC", 1, []byte("bad"))

	ctx := context.Background()
	count, err := dao.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestRemoteMACDAO_DeleteExpired_ListStorageError verifies storage errors
// are propagated during delete expired.
func TestRemoteMACDAO_DeleteExpired_ListStorageError(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.DeleteExpired(ctx)
	require.Error(t, err)
}
