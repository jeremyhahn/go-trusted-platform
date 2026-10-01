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

package switchsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func envelope(payload interface{}) []byte {
	resp := response.WebServiceResponse{
		Code:    200,
		Success: true,
		Payload: payload,
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestNewClient_NilHTTPClient(t *testing.T) {
	_, err := NewClient("https://example.com", nil)
	assert.Error(t, err)
	assert.IsType(t, ErrNilHTTPClient{}, err)
}

func TestNewClient_EmptyBaseURL(t *testing.T) {
	_, err := NewClient("", &http.Client{})
	assert.Error(t, err)
	assert.IsType(t, ErrEmptyBaseURL{}, err)
}

func TestNewClient_Success(t *testing.T) {
	c, err := NewClient("https://example.com", &http.Client{})
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c, err := NewClient("https://example.com/", &http.Client{})
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", c.baseURL)
}

func TestListPorts_Success(t *testing.T) {
	ports := []*switchmgmt.PortStatus{
		{Port: "Eth1/1", Mode: switchmgmt.PortModeAccess, AccessVLAN: 100, Enabled: true, LinkUp: true},
		{Port: "Eth1/2", Mode: switchmgmt.PortModeTrunk, TrunkVLANs: []uint16{100, 200}, Enabled: true},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "/api/v1/switches/core-01/ports")
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope(ports))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	result, err := c.ListPorts(context.Background(), "core-01")
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "Eth1/1", result[0].Port)
	assert.Equal(t, switchmgmt.PortModeAccess, result[0].Mode)
}

func TestListPorts_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	_, err = c.ListPorts(context.Background(), "core-01")
	assert.Error(t, err)
}

func TestGetPortStatus_Success(t *testing.T) {
	port := &switchmgmt.PortStatus{
		Port:        "Eth1/3",
		Mode:        switchmgmt.PortModeAccess,
		AccessVLAN:  200,
		Enabled:     true,
		LinkUp:      true,
		Description: "server-01",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope(port))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	result, err := c.GetPortStatus(context.Background(), "core-01", "Eth1/3")
	require.NoError(t, err)
	assert.Equal(t, "Eth1/3", result.Port)
	assert.Equal(t, uint16(200), result.AccessVLAN)
}

// TestGetPortStatus_TrunkNativeVLAN decodes a hypervisor-class trunk's
// allowed list and native VLAN over the REST transport.
func TestGetPortStatus_TrunkNativeVLAN(t *testing.T) {
	port := &switchmgmt.PortStatus{
		Port:       "Eth1/25",
		Mode:       switchmgmt.PortModeTrunk,
		TrunkVLANs: []uint16{401, 403, 404, 405, 406, 407, 408},
		NativeVLAN: 405,
		Enabled:    true,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope(port))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)
	result, err := c.GetPortStatus(context.Background(), "core-01", "Eth1/25")
	require.NoError(t, err)
	assert.Equal(t, uint16(405), result.NativeVLAN)
	assert.Equal(t, port.TrunkVLANs, result.TrunkVLANs)
}

func TestGetPortStatus_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	_, err = c.GetPortStatus(context.Background(), "core-01", "Eth99/99")
	assert.Error(t, err)
}

func TestSetPortVLAN_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/vlan")

		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, float64(200), body["vlan_id"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.SetPortVLAN(context.Background(), "core-01", "Eth1/3", 200)
	require.NoError(t, err)
}

func TestSetPortVLAN_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid vlan"))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.SetPortVLAN(context.Background(), "core-01", "Eth1/3", 5000)
	assert.Error(t, err)
}

func TestEnablePort_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/enable")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.EnablePort(context.Background(), "core-01", "Eth1/3")
	require.NoError(t, err)
}

func TestEnablePort_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ssh failed"))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.EnablePort(context.Background(), "core-01", "Eth1/3")
	assert.Error(t, err)
}

func TestDisablePort_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/disable")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.DisablePort(context.Background(), "core-01", "Eth1/3")
	require.NoError(t, err)
}

func TestDisablePort_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("ssh failed"))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, server.Client())
	require.NoError(t, err)

	err = c.DisablePort(context.Background(), "core-01", "Eth1/3")
	assert.Error(t, err)
}
