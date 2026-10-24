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

package pxe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// listingPXEServer records the ListDevices request it is handed.
type listingPXEServer struct {
	platformv1.UnimplementedPXEServiceServer
	got *platformv1.ListPXEDevicesRequest
}

func (s *listingPXEServer) ListDevices(_ context.Context, req *platformv1.ListPXEDevicesRequest) (*platformv1.ListPXEDevicesResponse, error) {
	s.got = req
	return &platformv1.ListPXEDevicesResponse{}, nil
}

func TestDeviceFilter_ReadsEveryFilterParameter(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  *platformv1.PXEDeviceFilter
	}{
		{"no parameters match every device", "", &platformv1.PXEDeviceFilter{}},
		{"empty values are absent", "state=&mac_address=&vlan=", &platformv1.PXEDeviceFilter{}},
		{"short state name", "state=quarantined",
			&platformv1.PXEDeviceFilter{State: platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED}},
		{"enum state name, as the SDK sends it", "state=PROVISIONING_STATE_INSTALL_COMPLETE",
			&platformv1.PXEDeviceFilter{State: platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE}},
		{"full MAC", "mac_address=52:54:00:aa:bb:cc", &platformv1.PXEDeviceFilter{MacAddress: "52:54:00:aa:bb:cc"}},
		{"MAC prefix", "mac_address=52:54:00", &platformv1.PXEDeviceFilter{MacAddress: "52:54:00"}},
		{"lowest VLAN", "vlan=1", &platformv1.PXEDeviceFilter{Vlan: 1}},
		{"highest VLAN", "vlan=4094", &platformv1.PXEDeviceFilter{Vlan: 4094}},
		{"all three", "state=booting&mac_address=52:54&vlan=405", &platformv1.PXEDeviceFilter{
			State: platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING, MacAddress: "52:54", Vlan: 405,
		}},
		{"a page", "limit=10&offset=20", &platformv1.PXEDeviceFilter{Limit: 10, Offset: 20}},
		{"zero limit and offset are no page", "limit=0&offset=0", &platformv1.PXEDeviceFilter{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, err := url.ParseQuery(tc.query)
			require.NoError(t, err)
			got, err := deviceFilter(query)
			require.NoError(t, err)
			assert.True(t, proto.Equal(tc.want, got), "want %v, got %v", tc.want, got)
		})
	}
}

func TestDeviceFilter_RefusesAValueThatCannotBeAFilter(t *testing.T) {
	cases := []struct {
		query     string
		parameter string
	}{
		{"state=sleeping", filterState},
		{"state=unspecified", filterState},
		{"state=PROVISIONING_STATE_UNSPECIFIED", filterState},
		{"mac_address=zz:zz", filterMAC},
		{"mac_address=52-54-00", filterMAC},
		{"mac_address=52:54:00:aa:bb:cc:dd", filterMAC},
		{"vlan=0", filterVLAN},
		{"vlan=4095", filterVLAN},
		{"vlan=-1", filterVLAN},
		{"vlan=70000", filterVLAN},
		{"vlan=ten", filterVLAN},
		{"limit=-1", filterLimit},
		{"limit=many", filterLimit},
		{"limit=3000000000", filterLimit},
		{"offset=-5", filterOffset},
		{"offset=1.5", filterOffset},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			query, err := url.ParseQuery(tc.query)
			require.NoError(t, err)
			_, err = deviceFilter(query)
			var invalid *ErrInvalidDeviceFilter
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tc.parameter, invalid.Parameter)
		})
	}
}

func TestListDevices_HandsTheQueryFilterToTheService(t *testing.T) {
	server := &listingPXEServer{}
	router := pxeRoutes(server)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices?state=authorized&mac_address=52:54:00&vlan=200&limit=5&offset=1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, server.got)
	want := &platformv1.PXEDeviceFilter{
		State: platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED, MacAddress: "52:54:00", Vlan: 200,
		Limit: 5, Offset: 1,
	}
	assert.True(t, proto.Equal(want, server.got.GetFilter()), "got %v", server.got.GetFilter())
}

func TestListDevices_RefusesABadFilterBeforeTheService(t *testing.T) {
	server := &listingPXEServer{}
	router := pxeRoutes(server)

	for _, query := range []string{"state=sleeping", "mac_address=nope", "vlan=4095", "limit=-1", "offset=x"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices?"+query, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, query)
	}
	assert.Nil(t, server.got, "a bad filter reached the service")
}
