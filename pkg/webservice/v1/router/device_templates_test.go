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

package router

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/device"
)

// newSeededTemplateMux mounts the CRUD device router and the bootstrap
// seeder router on one mux in the order pkg/webservice/v1/router.go's
// deviceRoutes registers them, over real template and profile services, so
// the test exercises the route that actually answers the seeder.
func newSeededTemplateMux(t *testing.T) *mux.Router {
	t.Helper()

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ds := device.NewDatastore(storage, logger)

	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)

	writer := response.NewResponseWriter(logger, nil)
	m := mux.NewRouter()
	NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		wsdevice.NewCRUDHandler(logger, writer, nil, profiles),
		wsdevice.NewTemplateHandler(logger, writer, templates, profiles), nil, nil).RegisterRoutes(m)
	restdevice.NewDeviceRouter(logger, writer, templates, profiles).RegisterRoutes(m)
	return m
}

// TestDeviceRouter_SeederOwnsPluralTemplatePost pins route ownership: with
// both routers mounted in platformd's order, POST /devices/templates is
// answered by the bootstrap seeder handler — its 201 payload is `{id}` only —
// and the CRUD create handler, whose payload is the full template, answers
// only the singular POST /device/templates.
func TestDeviceRouter_SeederOwnsPluralTemplatePost(t *testing.T) {
	m := newSeededTemplateMux(t)

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/devices/templates",
		strings.NewReader(`{"role":"worker","template":{"domain":"example.com"}}`)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var seeded struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &seeded))
	assert.Contains(t, seeded.Payload, "id")
	assert.NotContains(t, seeded.Payload, "name", "the CRUD handler answered the seeder's route")

	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/device/templates",
		strings.NewReader(`{"template":{"name":"gw-default","role":"gateway"}}`)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var crud struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &crud))
	assert.JSONEq(t, `"gw-default"`, string(crud.Payload["name"]))
}

// TestDeviceRouter_SeededTemplatesListWithNameAndRole reproduces #114: the
// seeder's {role, template} upload for control-plane, gateway and worker
// must list back with the name and role intact and the deterministic id.
func TestDeviceRouter_SeededTemplatesListWithNameAndRole(t *testing.T) {
	m := newSeededTemplateMux(t)
	roles := []string{"control-plane", "gateway", "worker"}

	for _, role := range roles {
		body := `{"role":"` + role + `","template":{"domain":"` + role + `.example.com"}}`
		req := httptest.NewRequest(http.MethodPost, "/devices/templates", strings.NewReader(body))
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		var envelope struct {
			Payload struct {
				ID string `json:"id"`
			} `json:"payload"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
		assert.Equal(t, strconv.FormatUint(util.NewID([]byte(role)), 10), envelope.Payload.ID)
	}

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices/templates", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var list struct {
		Payload struct {
			Templates []struct {
				ID     string          `json:"id"`
				Name   string          `json:"name"`
				Role   string          `json:"role"`
				Config json.RawMessage `json:"config"`
			} `json:"templates"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Payload.Templates, len(roles))

	listed := map[string]string{}
	for _, tmpl := range list.Payload.Templates {
		assert.Equal(t, tmpl.Role, tmpl.Name)
		assert.NotEmpty(t, tmpl.Config, "config dropped for %s", tmpl.Name)
		listed[tmpl.Name] = tmpl.Role
	}
	for _, role := range roles {
		assert.Equal(t, role, listed[role])
	}
}

// TestDeviceRouter_SeededTemplateUnknownRoleRejected verifies the colliding
// route answers an out-of-vocabulary role with 400 instead of storing it.
func TestDeviceRouter_SeededTemplateUnknownRoleRejected(t *testing.T) {
	m := newSeededTemplateMux(t)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates",
		strings.NewReader(`{"role":"compute","template":{"domain":"example.com"}}`))
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices/templates", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"templates":[]`)
}
