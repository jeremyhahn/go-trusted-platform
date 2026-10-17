//go:build integration

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

package tenant

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenantpkg "github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

func TestMCPAdapterDecodeTenantWrite(t *testing.T) {
	reply := json.RawMessage(`{"success":true,"message":"created","tenant":{
		"id":"t-1","name":"acme","display_name":"Acme","state":"active",
		"created_at":"2026-10-17T08:00:00Z","updated_at":"2026-10-17T08:00:00Z",
		"compute_quota":{"max_vms":10,"max_containers":0,"max_vcpus":4,"max_memory_mb":8192}}}`)

	tenant, err := decodeTenantWrite("CreateTenant", reply)
	require.NoError(t, err)
	assert.Equal(t, "t-1", tenant.ID, "the ID comes from the nested tenant, not the status envelope")
	assert.Equal(t, "acme", tenant.Name)
	assert.Equal(t, tenantpkg.StateActive, tenant.State)
	require.NotNil(t, tenant.ComputeQuota)
	assert.Equal(t, int64(10), tenant.ComputeQuota.MaxVMs)
}

func TestMCPAdapterDecodeTenantWrite_NoTenant(t *testing.T) {
	for name, reply := range map[string]string{
		"bare tenant":   `{"id":"t-1","name":"acme"}`,
		"null tenant":   `{"success":false,"message":"refused","tenant":null}`,
		"not an object": `[1]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeTenantWrite("UpdateTenant", json.RawMessage(reply))
			var failed ErrMCPRequestFailed
			require.True(t, errors.As(err, &failed), "a reply without a nested tenant is an error, not an empty tenant")
			assert.Equal(t, "UpdateTenant", failed.Operation)
		})
	}
}

func TestMCPAdapterDecodeUsage(t *testing.T) {
	usage, err := decodeUsage(json.RawMessage(`{"tenant_id":"t-1","usage":{"vms":2,"vcpus":8,"memory_mb":4096,"snapshots":1},"timestamp":""}`))
	require.NoError(t, err)
	assert.Equal(t, &GetUsageResult{TenantID: "t-1", VMs: 2, VCPUs: 8, MemoryMB: 4096, Snapshots: 1}, usage)

	_, err = decodeUsage(json.RawMessage(`{"usage":"none"}`))
	var failed ErrMCPRequestFailed
	assert.True(t, errors.As(err, &failed), "a malformed usage reply is a typed error")
}

func TestMCPAdapterDecodeCheckQuota(t *testing.T) {
	check, err := decodeCheckQuota(json.RawMessage(`{"tenant_id":"t-1","resource_type":"vms","amount":3,"available":true,"message":"ok"}`))
	require.NoError(t, err)
	assert.Equal(t, &CheckQuotaResult{TenantID: "t-1", Resource: "vms", Amount: 3, Allowed: true, Message: "ok"}, check)

	_, err = decodeCheckQuota(json.RawMessage(`{"available":"yes"}`))
	var failed ErrMCPRequestFailed
	assert.True(t, errors.As(err, &failed), "a malformed check reply is a typed error")
}

func TestMCPAdapterQuotaUpdateArgs(t *testing.T) {
	args := quotaUpdateArgs(UpdateQuotasOptions{
		TenantID: "t-1",
		Compute:  &ComputeQuotaUpdate{MaxVMs: 20, MaxDiskGB: 500},
		Storage:  &StorageQuotaUpdate{MaxSnapshots: 5},
	})
	assert.Equal(t, map[string]interface{}{
		"tenant_id":      "t-1",
		"max_vms":        int64(20),
		"max_containers": int64(0),
		"max_vcpus":      int64(0),
		"max_memory_mb":  int64(0),
		"max_volumes_gb": int64(0),
		"max_snapshots":  int64(5),
	}, args, "limits are top-level keys; network left out, disk has no tool argument")

	assert.Equal(t, map[string]interface{}{"tenant_id": "t-2"}, quotaUpdateArgs(UpdateQuotasOptions{TenantID: "t-2"}))
}
