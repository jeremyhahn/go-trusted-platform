// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package router

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/device"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// deviceSDKServer is the device router platformd serves under /api/v1, over
// real device, profile and template services, reached by the SDK's REST
// transport exactly as `platformctl --transport rest` reaches it.
type deviceSDKServer struct {
	client    platformv1.DeviceServiceClient
	devices   *device.Service
	profiles  *device.ProfileService
	templates *device.TemplateService
}

// newDeviceSDKServer serves the real device handlers behind a TLS test server
// and connects the SDK REST adapter to it, so every request body the SDK
// sends is decoded by the handler's own request type and every reply the SDK
// decodes is the handler's own response.
func newDeviceSDKServer(t *testing.T) *deviceSDKServer {
	t.Helper()

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ds := device.NewDatastore(storage, logger)

	devices, err := device.NewService(ds)
	require.NoError(t, err)
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)

	writer := response.NewResponseWriter(logger, nil)
	root := mux.NewRouter()
	v1 := root.PathPrefix("/api/v1").Subrouter()
	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		wsdevice.NewCRUDHandler(logger, writer, devices, profiles),
		wsdevice.NewTemplateHandler(logger, writer, templates, profiles, nil), nil, nil)
	require.NoError(t, err)
	deviceRouter.RegisterRoutes(v1)
	restdevice.NewDeviceRouter(logger, writer, templates, profiles).RegisterRoutes(v1)

	return &deviceSDKServer{
		client:    connectDeviceSDK(t, root),
		devices:   devices,
		profiles:  profiles,
		templates: templates,
	}
}

// connectDeviceSDK serves root over TLS, adds the health route the SDK REST
// transport probes on connect, and returns the SDK device client bound to it.
func connectDeviceSDK(t *testing.T, root *mux.Router) platformv1.DeviceServiceClient {
	t.Helper()

	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewDeviceServiceClient(adapter.Connection())
}

// sdkProfile is a profile with every field the REST profile handlers store.
func sdkProfile() *platformv1.DeviceProfile {
	return &platformv1.DeviceProfile{
		Id:                    3,
		Name:                  "edge-node",
		Zone:                  "edge",
		Model:                 "r650",
		Role:                  platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
		EkSerial:              "EK-1",
		MacAddress:            "aa:bb:cc:dd:ee:ff",
		Config:                []byte(`{"hostname":"edge-1"}`),
		TlsServerName:         "compute.example.internal",
		EnrollmentNetwork:     "provisioning",
		PostEnrollmentNetwork: "admitted",
		FailureNetwork:        "quarantine",
		PlatformdConfig:       &platformv1.PlatformdConfigRef{ConfigType: "reference", Reference: "base"},
		MatchRules:            &platformv1.ProfileMatchRules{MacPrefix: "aa:bb", Model: "r650"},
		Networks: map[string]*platformv1.NetworkPhaseConfig{
			"admitted": {
				Vlan:       100,
				AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
				Dns:        []string{"10.0.0.53"},
				Acls:       []*platformv1.ACLConfig{{Priority: 10, Protocol: "tcp", DstPort: 443, Action: "allow"}},
			},
		},
	}
}

// assertStoredProfile verifies the stored profile carries every field of
// sdkProfile under the given name.
func assertStoredProfile(t *testing.T, stored *entities.DeviceProfile, name string) {
	t.Helper()

	assert.Equal(t, name, stored.Name)
	assert.Equal(t, "edge", stored.Zone)
	assert.Equal(t, "r650", stored.Model)
	assert.Equal(t, entities.DeviceRoleLoadBalancer, stored.Role)
	assert.Equal(t, "EK-1", stored.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", stored.MACAddress)
	assert.Equal(t, "compute.example.internal", stored.TLSServerName)
	assert.Equal(t, "provisioning", stored.EnrollmentNetwork)
	assert.Equal(t, "admitted", stored.PostEnrollmentNetwork)
	assert.Equal(t, "quarantine", stored.FailureNetwork)

	config, err := json.Marshal(stored.Config)
	require.NoError(t, err)
	assert.JSONEq(t, `{"hostname":"edge-1"}`, string(config))

	require.NotNil(t, stored.PlatformdConfig)
	assert.Equal(t, "reference", stored.PlatformdConfig.ConfigType)
	assert.Equal(t, "base", stored.PlatformdConfig.Reference)
	require.NotNil(t, stored.MatchRules)
	assert.Equal(t, "aa:bb", stored.MatchRules.MACPrefix)
	assert.Equal(t, "r650", stored.MatchRules.Model)

	require.Contains(t, stored.Networks, "admitted")
	admitted := stored.Networks["admitted"]
	assert.Equal(t, uint16(100), admitted.VLAN)
	assert.Equal(t, entities.AuthMethod802_1X, admitted.AuthMethod)
	assert.Equal(t, []string{"10.0.0.53"}, admitted.DNS)
	assert.Equal(t, []entities.ACLConfig{{Priority: 10, Protocol: "tcp", DstPort: 443, Action: "allow"}}, admitted.ACLs)
}

// TestDeviceSDKREST_ProfileWritesKeepEveryField drives CreateProfile and then
// UpdateProfile through the SDK against the real handlers: the update must
// replace the name and keep every other field, where the nested body the SDK
// used to send left the handler an empty profile to save.
func TestDeviceSDKREST_ProfileWritesKeepEveryField(t *testing.T) {
	srv := newDeviceSDKServer(t)
	ctx := context.Background()

	created, err := srv.client.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: sdkProfile()})
	require.NoError(t, err)
	require.NotNil(t, created.GetProfile(), "the reply lost the created profile")
	assert.Equal(t, uint64(3), created.GetProfile().GetId())
	assert.Equal(t, "edge-node", created.GetProfile().GetName())

	stored, err := srv.profiles.Get(ctx, 3)
	require.NoError(t, err)
	assertStoredProfile(t, stored, "edge-node")

	update := sdkProfile()
	update.Name = "edge-node-renamed"
	updated, err := srv.client.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: update})
	require.NoError(t, err)
	require.NotNil(t, updated.GetProfile(), "the reply lost the updated profile")
	assert.Equal(t, "edge-node-renamed", updated.GetProfile().GetName())
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER, updated.GetProfile().GetRole())

	stored, err = srv.profiles.Get(ctx, 3)
	require.NoError(t, err)
	assertStoredProfile(t, stored, "edge-node-renamed")
}

// TestDeviceSDKREST_ProfileWriteRejectedByTheHandler verifies a body the
// handler refuses comes back as InvalidArgument and stores nothing.
func TestDeviceSDKREST_ProfileWriteRejectedByTheHandler(t *testing.T) {
	srv := newDeviceSDKServer(t)
	ctx := context.Background()

	profile := sdkProfile()
	profile.EkCert = "not a PEM certificate"
	_, err := srv.client.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: profile})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())

	_, err = srv.profiles.Get(ctx, 3)
	assert.Error(t, err, "a rejected profile was stored")
}

// TestDeviceSDKREST_CreateProfileFromTemplateKeepsOverrides verifies the
// overrides the SDK sends reach the template handler's
// CreateProfileFromTemplateRequest and the reply carries the new profile.
func TestDeviceSDKREST_CreateProfileFromTemplateKeepsOverrides(t *testing.T) {
	srv := newDeviceSDKServer(t)
	ctx := context.Background()

	require.NoError(t, srv.templates.Save(ctx, &entities.DeviceTemplate{
		ID:   41,
		Name: "edge-template",
		Role: entities.DeviceRoleEdge,
	}))

	overrides := sdkProfile()
	resp, err := srv.client.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{
		TemplateId: 41,
		Overrides:  overrides,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetProfile(), "the reply lost the created profile")
	assert.Equal(t, "edge-node", resp.GetProfile().GetName())

	stored, err := srv.profiles.Get(ctx, resp.GetProfile().GetId())
	require.NoError(t, err)
	assert.Equal(t, "edge-node", stored.Name)
	assert.Equal(t, "edge", stored.Zone)
	assert.Equal(t, "r650", stored.Model)
	assert.Equal(t, entities.DeviceRoleLoadBalancer, stored.Role)
	assert.Equal(t, "EK-1", stored.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", stored.MACAddress)
	require.Contains(t, stored.Networks, "admitted")
	assert.Equal(t, uint16(100), stored.Networks["admitted"].VLAN)
	assert.Equal(t, entities.AuthMethod802_1X, stored.Networks["admitted"].AuthMethod)
}

// TestDeviceSDKREST_CreateProfileFromUnknownTemplate verifies a missing
// template is an error, not an empty reply.
func TestDeviceSDKREST_CreateProfileFromUnknownTemplate(t *testing.T) {
	srv := newDeviceSDKServer(t)

	resp, err := srv.client.CreateProfileFromTemplate(context.Background(),
		&platformv1.CreateProfileFromTemplateRequest{TemplateId: 404, Overrides: sdkProfile()})
	require.Error(t, err)
	assert.Nil(t, resp)
}

// TestDeviceSDKREST_RegisterReturnsTheDevice is `platformctl device register
// --transport rest`: the SDK device client's Create must return the device
// the handler stored, not nil.
func TestDeviceSDKREST_RegisterReturnsTheDevice(t *testing.T) {
	srv := newDeviceSDKServer(t)
	ctx := context.Background()

	created, err := sdkdevice.NewClientFromGRPC(srv.client).Create(ctx, &platformv1.Device{
		Serial:     "SN-0001",
		Model:      "r640",
		HashAlgoId: 11,
	})
	require.NoError(t, err)
	require.NotNil(t, created, "the REST reply lost the registered device")
	assert.NotZero(t, created.GetId())
	assert.Equal(t, "SN-0001", created.GetSerial())
	assert.Equal(t, "r640", created.GetModel())
	assert.Equal(t, uint32(11), created.GetHashAlgoId())

	stored, err := srv.devices.Get(ctx, created.GetId())
	require.NoError(t, err)
	assert.Equal(t, "SN-0001", stored.Serial)

	fetched, err := srv.client.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: created.GetId()})
	require.NoError(t, err)
	require.NotNil(t, fetched.GetDevice())
	assert.Equal(t, "SN-0001", fetched.GetDevice().GetSerial())
}

// TestDeviceSDKREST_GetUnknownDevice verifies a missing device is NotFound.
func TestDeviceSDKREST_GetUnknownDevice(t *testing.T) {
	srv := newDeviceSDKServer(t)

	_, err := srv.client.GetDevice(context.Background(), &platformv1.GetDeviceRequest{Id: 404})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), err.Error())
}
