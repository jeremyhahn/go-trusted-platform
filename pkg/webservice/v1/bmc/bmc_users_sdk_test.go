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

package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// newBMCUsersSDKClient serves the real BMC user handlers on the daemon's
// routes and returns an SDK BMC client that reaches them over the REST
// adapter, so the request and response translations are proven against
// the handler rather than against handwritten JSON.
func newBMCUsersSDKClient(t *testing.T, svc *mockBMCService) platformv1.BMCServiceClient {
	t.Helper()
	logger := newTestLogger()
	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		BMCService:     svc,
		ResponseWriter: response.NewResponseWriter(logger, nil),
	})
	require.NoError(t, err)

	router := mux.NewRouter()
	// The SDK REST adapter probes liveness when it connects.
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users", h.ListUsers).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users", h.CreateUser).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege", h.SetUserPrivilege).Methods(http.MethodPut)

	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return platformv1.NewBMCServiceClient(conn.(*sdkrest.Adapter).Connection())
}

func TestBMCUsersSDKRoundTrip_ListUsers(t *testing.T) {
	var gotProfile uint64
	svc := &mockBMCService{listUsersFn: func(_ context.Context, id uint64) ([]bmcpkg.User, error) {
		gotProfile = id
		return []bmcpkg.User{
			{Slot: 2, Username: "admin", Enabled: true, Privilege: bmcpkg.PrivilegeAdministrator, Channel: 1},
			{Slot: 3, Username: "viewer", Enabled: false, Privilege: bmcpkg.PrivilegeUser, Channel: 1},
		}, nil
	}}
	client := newBMCUsersSDKClient(t, svc)

	resp, err := client.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{ProfileId: 7})
	require.NoError(t, err)
	assert.Equal(t, uint64(7), gotProfile)
	require.Len(t, resp.GetUsers(), 2)

	admin := resp.GetUsers()[0]
	assert.Equal(t, uint32(2), admin.GetSlot())
	assert.Equal(t, "admin", admin.GetUsername())
	assert.True(t, admin.GetEnabled())
	assert.Equal(t, platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR, admin.GetPrivilege())
	assert.Equal(t, uint32(1), admin.GetChannel())

	viewer := resp.GetUsers()[1]
	assert.Equal(t, uint32(3), viewer.GetSlot())
	assert.Equal(t, "viewer", viewer.GetUsername())
	assert.False(t, viewer.GetEnabled())
	assert.Equal(t, platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER, viewer.GetPrivilege())
}

func TestBMCUsersSDKRoundTrip_CreateUser(t *testing.T) {
	var (
		gotProfile  uint64
		gotUser     bmcpkg.User
		gotPassword string
	)
	svc := &mockBMCService{createUserFn: func(_ context.Context, id uint64, user bmcpkg.User, password string) error {
		gotProfile, gotUser, gotPassword = id, user, password
		return nil
	}}
	client := newBMCUsersSDKClient(t, svc)

	resp, err := client.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 9,
		User: &platformv1.BMCUser{
			Slot:      4,
			Username:  "operator1",
			Enabled:   true,
			Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
			Channel:   1,
		},
		Password: "s3cret-Pass",
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(4), resp.GetSlot())

	assert.Equal(t, uint64(9), gotProfile)
	assert.Equal(t, bmcpkg.User{
		Slot:      4,
		Username:  "operator1",
		Enabled:   true,
		Privilege: bmcpkg.PrivilegeOperator,
		Channel:   1,
	}, gotUser)
	assert.Equal(t, "s3cret-Pass", gotPassword)
}

func TestBMCUsersSDKRoundTrip_OccupiedSlotIsConflict(t *testing.T) {
	svc := &mockBMCService{createUserFn: func(context.Context, uint64, bmcpkg.User, string) error {
		return bmcpkg.ErrSlotOccupied{Slot: 4}
	}}
	client := newBMCUsersSDKClient(t, svc)

	_, err := client.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 9,
		User: &platformv1.BMCUser{
			Slot:      4,
			Username:  "operator1",
			Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
		},
		Password: "s3cret-Pass",
	})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestBMCUsersSDKRoundTrip_SetUserPrivilege(t *testing.T) {
	var (
		gotProfile    uint64
		gotSlot       uint8
		gotChannel    uint8
		gotPrivilege  bmcpkg.Privilege
		backendCalled bool
	)
	svc := &mockBMCService{setUserPrivilegeFn: func(_ context.Context, id uint64, slot, channel uint8, priv bmcpkg.Privilege) error {
		backendCalled = true
		gotProfile, gotSlot, gotChannel, gotPrivilege = id, slot, channel, priv
		return nil
	}}
	client := newBMCUsersSDKClient(t, svc)

	_, err := client.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 11,
		Slot:      5,
		Channel:   2,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS,
	})
	require.NoError(t, err)
	require.True(t, backendCalled)
	assert.Equal(t, uint64(11), gotProfile)
	assert.Equal(t, uint8(5), gotSlot)
	assert.Equal(t, uint8(2), gotChannel)
	assert.Equal(t, bmcpkg.PrivilegeNoAccess, gotPrivilege)
}

func TestBMCUsersSDKRoundTrip_UnknownProfileIsNotFound(t *testing.T) {
	svc := &mockBMCService{listUsersFn: func(_ context.Context, id uint64) ([]bmcpkg.User, error) {
		return nil, bmcpkg.ErrProfileNotFound{ProfileID: id}
	}}
	client := newBMCUsersSDKClient(t, svc)

	_, err := client.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{ProfileId: 404})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestBMCUsersSDKRoundTrip_UnspecifiedPrivilegeRefusedBeforeBackend(t *testing.T) {
	svc := &mockBMCService{setUserPrivilegeFn: func(context.Context, uint64, uint8, uint8, bmcpkg.Privilege) error {
		t.Fatal("backend must not be reached for an unspecified privilege")
		return nil
	}}
	client := newBMCUsersSDKClient(t, svc)

	_, err := client.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1,
		Slot:      2,
	})
	require.Error(t, err)
}
