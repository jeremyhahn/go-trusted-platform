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

//go:build codec_msgpack

package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// missingDeviceID is the device the operator fake answers NotFound for.
const missingDeviceID = "404"

// operatorDeviceServer answers the lifecycle and attest-cert RPCs, recording
// each request, and NotFound for missingDeviceID.
type operatorDeviceServer struct {
	platformv1.UnimplementedDeviceServiceServer

	disabled *platformv1.DisableDeviceRequest
	enabled  *platformv1.EnableDeviceRequest
	recorded *platformv1.RecordAttestationCertificateRequest
}

func (s *operatorDeviceServer) DisableDevice(_ context.Context, req *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	if req.GetDeviceId() == missingDeviceID {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	s.disabled = req
	return &platformv1.DeviceLifecycleResponse{}, nil
}

func (s *operatorDeviceServer) EnableDevice(_ context.Context, req *platformv1.EnableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	if req.GetDeviceId() == missingDeviceID {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	s.enabled = req
	return &platformv1.DeviceLifecycleResponse{}, nil
}

func (s *operatorDeviceServer) RecordAttestationCertificate(
	_ context.Context,
	req *platformv1.RecordAttestationCertificateRequest,
) (*platformv1.RecordAttestationCertificateResponse, error) {
	if req.GetDeviceId() == missingDeviceID {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	s.recorded = req
	return &platformv1.RecordAttestationCertificateResponse{}, nil
}

// deviceOperatorFixture is a daemon REST server with the operator routes and
// pkg/api/rest's device routes mounted in daemon.go's order, over the real
// device, profile and template services on one in-memory datastore.
type deviceOperatorFixture struct {
	server *RESTServer
	rpc    *operatorDeviceServer
	writer string
	reader string
}

func newDeviceOperatorFixture(t *testing.T) *deviceOperatorFixture {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	ds := device.NewDatastore(storage, logging.DefaultLogger())
	devices, err := device.NewService(ds)
	require.NoError(t, err)
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)

	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	f := &deviceOperatorFixture{
		server: newTPMTestRESTServer(t),
		rpc:    &operatorDeviceServer{},
		writer: key.sign(t, "operator", "", []string{"device:read", "device:write", "device:delete"}),
		reader: key.sign(t, "operator", "", []string{"device:read"}),
	}
	f.server.SetDeviceOperatorHandlers(DeviceOperatorServices{
		Devices:   devices,
		Profiles:  profiles,
		Templates: templates,
		Server:    f.rpc,
	}, restapi.NewScopeGuard(validator, nil, slog.Default()))
	f.server.SetDeviceHandlers(devices, profiles, f.rpc)
	return f
}

// payload decodes the {code, success, payload} envelope's payload into out.
func payload(t *testing.T, body []byte, out any) {
	t.Helper()
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	require.NoError(t, json.Unmarshal(envelope.Payload, out), string(envelope.Payload))
}

func TestRESTServer_SetDeviceOperatorHandlers_NoServicesMountsNothing(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)

	server.SetDeviceOperatorHandlers(DeviceOperatorServices{}, restapi.NewScopeGuard(nil, nil, slog.Default()))

	assert.Equal(t, http.StatusNotFound, serveTPMRoute(server, http.MethodPost, "/api/v1/device/templates", "token").Code)
	assert.Equal(t, http.StatusNotFound, serveTPMRoute(server, http.MethodGet, "/api/v1/devices/count", "token").Code)
}

func TestRESTServer_DeviceOperator_Templates(t *testing.T) {
	t.Parallel()
	f := newDeviceOperatorFixture(t)

	created := serveTPMBody(f.server, http.MethodPost, "/api/v1/device/templates", f.writer,
		`{"name":"edge","description":"edge nodes","config":"aG9zdG5hbWU6IGVkZ2UtMDEK"}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var template struct {
		ID   json.Number `json:"id"`
		Name string      `json:"name"`
	}
	payload(t, created.Body.Bytes(), &template)
	assert.Equal(t, "edge", template.Name)

	t.Run("get returns the template it created", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/templates/"+template.ID.String(), f.reader)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `"edge"`)
	})

	t.Run("an unknown template is not found", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/templates/999", f.reader)
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a malformed body is refused", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/device/templates", f.writer, `{"name":`)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})

	t.Run("a device:read token cannot create", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/device/templates", f.reader, `{"name":"other"}`)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})

	t.Run("no token is refused", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/templates", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	})
}

func TestRESTServer_DeviceOperator_Profiles(t *testing.T) {
	t.Parallel()
	f := newDeviceOperatorFixture(t)

	created := serveTPMBody(f.server, http.MethodPost, "/api/v1/device/profiles", f.writer,
		`{"name":"rack-a","match_rules":{"mac_addresses":["00:11:22:33:44:55"]}}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var profile struct {
		ID json.Number `json:"id"`
	}
	payload(t, created.Body.Bytes(), &profile)

	t.Run("get by id under /device/profiles", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/profiles/"+profile.ID.String(), f.reader)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `"rack-a"`)
	})

	t.Run("count", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/profiles/count", f.reader)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var count struct {
			Count int `json:"count"`
		}
		payload(t, w.Body.Bytes(), &count)
		assert.Equal(t, 1, count.Count)
	})

	t.Run("an unknown profile is not found", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/device/profiles/999", f.reader)
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a malformed body is refused", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/device/profiles/match", f.reader, `{`)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})

	t.Run("a device:read token cannot delete", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodDelete, "/api/v1/device/profiles/"+profile.ID.String(), f.reader)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}

// TestRESTServer_DeviceOperator_CountPrecedesDeviceID pins the mount order
// daemon.go relies on: GET /api/v1/devices/count reaches the count, not
// pkg/api/rest's GET /api/v1/devices/{id} with id="count".
func TestRESTServer_DeviceOperator_CountPrecedesDeviceID(t *testing.T) {
	t.Parallel()
	f := newDeviceOperatorFixture(t)

	w := serveTPMRoute(f.server, http.MethodGet, "/api/v1/devices/count", f.reader)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var count struct {
		Count *int `json:"count"`
	}
	payload(t, w.Body.Bytes(), &count)
	require.NotNil(t, count.Count, w.Body.String())
	assert.Equal(t, 0, *count.Count)

	assert.Equal(t, http.StatusUnauthorized, serveTPMRoute(f.server, http.MethodGet, "/api/v1/devices/count", "").Code)
}

func TestRESTServer_DeviceOperator_Lifecycle(t *testing.T) {
	t.Parallel()
	f := newDeviceOperatorFixture(t)

	t.Run("disable reaches the device service with its reason", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/devices/7/disable", f.writer, `{"reason":"stolen"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, f.rpc.disabled)
		assert.Equal(t, "7", f.rpc.disabled.GetDeviceId())
		assert.Equal(t, "stolen", f.rpc.disabled.GetReason())
	})

	t.Run("enable reaches the device service", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodPost, "/api/v1/devices/7/enable", f.writer)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, f.rpc.enabled)
		assert.Equal(t, "7", f.rpc.enabled.GetDeviceId())
	})

	t.Run("an unknown device is not found", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodPost, "/api/v1/devices/"+missingDeviceID+"/disable", f.writer)
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a malformed body is refused", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/devices/7/disable", f.writer, `{"reason":`)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})

	t.Run("a device:read token cannot disable", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodPost, "/api/v1/devices/7/disable", f.reader)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}

func TestRESTServer_DeviceOperator_RecordAttestCert(t *testing.T) {
	t.Parallel()
	f := newDeviceOperatorFixture(t)

	t.Run("records through the device service", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/devices/7/attest-cert/record", f.writer, `{"reissue":true}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, f.rpc.recorded)
		assert.Equal(t, "7", f.rpc.recorded.GetDeviceId())
		assert.True(t, f.rpc.recorded.GetReissue())
	})

	t.Run("an unknown device is not found", func(t *testing.T) {
		w := serveTPMRoute(f.server, http.MethodPost, "/api/v1/devices/"+missingDeviceID+"/attest-cert/record", f.writer)
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a malformed body is refused", func(t *testing.T) {
		w := serveTPMBody(f.server, http.MethodPost, "/api/v1/devices/7/attest-cert/record", f.writer, `{"reissue":`)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})
}
