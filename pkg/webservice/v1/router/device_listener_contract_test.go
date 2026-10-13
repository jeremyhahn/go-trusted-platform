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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apirest "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// POST /api/v1/devices is served by two listeners: the webservice CRUD
// handler and the daemon REST handler. They once disagreed — one synthesised
// a serial for an empty body, the other refused it; one read the {device:{}}
// envelope, the other ignored it (#484). These tests hold them to one
// contract.

// seedDeviceID is a device present in every listener's store, so routes that
// take a device id reach their success path.
const seedDeviceID = 1

// deviceListener is one REST listener over its own, freshly seeded store.
type deviceListener struct {
	name    string
	router  *mux.Router
	devices *device.Service
}

// deviceListenerBuilders builds each listener that registers device routes.
var deviceListenerBuilders = []func(t *testing.T) deviceListener{
	newWebserviceDeviceListener,
	newDaemonDeviceListener,
}

func newDeviceStore(t *testing.T) (*device.Service, *device.ProfileService, *device.TemplateService, *logging.Logger) {
	t.Helper()

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.NewLogger(slog.LevelError, nil)
	ds := device.NewDatastore(storage, logger)

	devices, err := device.NewService(ds)
	require.NoError(t, err)
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)

	require.NoError(t, devices.Create(context.Background(),
		&entities.Device{ID: seedDeviceID, Serial: "SN-SEED", Model: "seed"}))
	return devices, profiles, templates, logger
}

func newWebserviceDeviceListener(t *testing.T) deviceListener {
	t.Helper()

	devices, profiles, templates, logger := newDeviceStore(t)
	writer := response.NewResponseWriter(logger, nil)
	root := mux.NewRouter()
	v1 := root.PathPrefix("/api/v1").Subrouter()
	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		wsdevice.NewCRUDHandler(logger, writer, devices, profiles),
		wsdevice.NewTemplateHandler(logger, writer, templates, profiles, nil), nil, nil)
	require.NoError(t, err)
	deviceRouter.RegisterRoutes(v1)
	return deviceListener{name: "webservice", router: root, devices: devices}
}

func newDaemonDeviceListener(t *testing.T) deviceListener {
	t.Helper()

	devices, profiles, _, _ := newDeviceStore(t)
	root := mux.NewRouter()
	apirest.NewDeviceHandlers(devices, profiles, slog.New(slog.DiscardHandler)).RegisterRoutes(root)
	return deviceListener{name: "daemon", router: root, devices: devices}
}

func (l deviceListener) serve(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	l.router.ServeHTTP(w, req)
	return w
}

// persisted returns the stored device with the fields the store assigns —
// id and timestamps — cleared, so two listeners' rows can be compared.
func (l deviceListener) persisted(t *testing.T, serial string) *entities.Device {
	t.Helper()

	d, err := l.devices.FindBySerial(context.Background(), serial)
	require.NoError(t, err, "%s: no device persisted with serial %q", l.name, serial)
	d.ID = 0
	d.CreatedAt = time.Time{}
	d.UpdatedAt = time.Time{}
	return d
}

func (l deviceListener) count(t *testing.T) int {
	t.Helper()

	n, err := l.devices.Count(context.Background())
	require.NoError(t, err)
	return n
}

// deviceBodies is the request corpus both the create table and the route
// guard post.
var deviceBodies = map[string]string{
	"flat":                 `{"serial":"SN-FLAT","model":"R640","attest_cert":"cert","hash_algo_id":11}`,
	"envelope":             `{"device":{"serial":"SN-ENV","model":"R640","attest_cert":"cert","hash_algo_id":11}}`,
	"split, agreeing":      `{"serial":"SN-SPLIT","device":{"serial":"SN-SPLIT","model":"R640"}}`,
	"console keys":         `{"serial":"SN-UI","name":"rack-3","type":"server","description":"d","tpm_version":"2.0","manufacturer":"Dell"}`,
	"empty serial":         `{"serial":"","model":"R640"}`,
	"empty object":         `{}`,
	"empty body":           ``,
	"conflicting":          `{"serial":"SN-FLAT","device":{"serial":"SN-ENV"}}`,
	"invalid JSON":         `{"serial":`,
	"invalid id":           `{"id":-1,"serial":"SN-BADID"}`,
	"name only (envelope)": `{"device":{"name":"rack-3"}}`,
	"duplicate serial":     `{"serial":"SN-SEED","model":"other"}`,
}

func TestDeviceCreate_BothListenersHonourOneContract(t *testing.T) {
	cases := []struct {
		body   string
		status int
		// want is the persisted row for an accepted body, ids and
		// timestamps aside.
		want *entities.Device
	}{
		{body: "flat", status: http.StatusCreated, want: &entities.Device{
			Serial: "SN-FLAT", Model: "R640", AttestCert: "cert", HashAlgoId: 11, State: entities.DeviceStateRegistered}},
		{body: "envelope", status: http.StatusCreated, want: &entities.Device{
			Serial: "SN-ENV", Model: "R640", AttestCert: "cert", HashAlgoId: 11, State: entities.DeviceStateRegistered}},
		{body: "split, agreeing", status: http.StatusCreated, want: &entities.Device{
			Serial: "SN-SPLIT", Model: "R640", State: entities.DeviceStateRegistered}},
		// The console's name, type, description and tpm_* keys have no
		// column and are dropped; manufacturer stands in for the model.
		{body: "console keys", status: http.StatusCreated, want: &entities.Device{
			Serial: "SN-UI", Model: "Dell", State: entities.DeviceStateRegistered}},
		{body: "empty serial", status: http.StatusBadRequest},
		{body: "empty object", status: http.StatusBadRequest},
		{body: "empty body", status: http.StatusBadRequest},
		{body: "conflicting", status: http.StatusBadRequest},
		{body: "invalid JSON", status: http.StatusBadRequest},
		{body: "invalid id", status: http.StatusBadRequest},
		{body: "name only (envelope)", status: http.StatusBadRequest},
		{body: "duplicate serial", status: http.StatusConflict},
	}
	require.Len(t, cases, len(deviceBodies), "every corpus body needs an expected outcome")

	for _, tc := range cases {
		body, ok := deviceBodies[tc.body]
		require.True(t, ok, "unknown corpus body %q", tc.body)

		t.Run(tc.body, func(t *testing.T) {
			for _, build := range deviceListenerBuilders {
				l := build(t)
				w := l.serve(http.MethodPost, "/api/v1/devices", body)

				require.Equal(t, tc.status, w.Code, "%s: %s", l.name, w.Body.String())
				if tc.want == nil {
					assert.Equal(t, 1, l.count(t), "%s: a refused create wrote a device", l.name)
					continue
				}
				assert.Equal(t, tc.want, l.persisted(t, tc.want.Serial), l.name)
			}
		})
	}
}

// TestDeviceCreate_GoSDKRegistersOnBothListeners drives the Go SDK REST
// transport — what `platformctl device register` uses over a REST context —
// against each listener. The SDK posts the proto envelope, which the daemon
// refused with a 400 until both listeners shared one decoder (#484).
func TestDeviceCreate_GoSDKRegistersOnBothListeners(t *testing.T) {
	for _, build := range deviceListenerBuilders {
		listener := build(t)
		t.Run(listener.name, func(t *testing.T) {
			client := sdkdevice.NewClientFromGRPC(connectDeviceSDK(t, listener.router))

			created, err := client.Create(context.Background(),
				&platformv1.Device{Serial: "SN-SDK", Model: "r640", HashAlgoId: 11})
			require.NoError(t, err)
			require.NotNil(t, created, "the REST reply lost the registered device")
			assert.NotZero(t, created.GetId())
			assert.Equal(t, "SN-SDK", created.GetSerial())

			assert.Equal(t, &entities.Device{
				Serial:     "SN-SDK",
				Model:      "r640",
				HashAlgoId: 11,
				State:      entities.DeviceStateRegistered,
			}, listener.persisted(t, "SN-SDK"))
		})
	}
}

// TestDeviceCreate_GoSDKIsRefusedAlikeOnBothListeners pins that a create the
// contract refuses reaches the SDK caller as an error, and writes nothing, on
// either listener.
func TestDeviceCreate_GoSDKIsRefusedAlikeOnBothListeners(t *testing.T) {
	refusals := map[string]struct {
		device *platformv1.Device
		code   codes.Code
	}{
		"no serial":    {&platformv1.Device{Model: "r640"}, codes.InvalidArgument},
		"taken serial": {&platformv1.Device{Serial: "SN-SEED"}, codes.AlreadyExists},
	}
	for _, build := range deviceListenerBuilders {
		listener := build(t)
		client := sdkdevice.NewClientFromGRPC(connectDeviceSDK(t, listener.router))
		for name, tc := range refusals {
			t.Run(listener.name+"/"+name, func(t *testing.T) {
				created, err := client.Create(context.Background(), tc.device)

				require.Error(t, err)
				assert.Equal(t, tc.code, status.Code(err))
				assert.Nil(t, created)
				assert.Equal(t, 1, listener.count(t), "a refused create must not write a device")
			})
		}
	}
}

// TestDeviceRoutes_SharedRoutesAgree is the general guard: wherever both
// listeners register the same method and path, the same body must get the
// same status from each. A route added to one listener with a contract of
// its own fails here, not in the field.
func TestDeviceRoutes_SharedRoutesAgree(t *testing.T) {
	shared := sharedBodyRoutes(t)
	assert.Contains(t, shared, routeKey{http.MethodPost, "/api/v1/devices"})
	assert.Contains(t, shared, routeKey{http.MethodPut, "/api/v1/devices/{id}"})

	for _, route := range shared {
		for name, body := range deviceBodies {
			t.Run(route.String()+"/"+name, func(t *testing.T) {
				statuses := map[string]int{}
				for _, build := range deviceListenerBuilders {
					l := build(t)
					statuses[l.name] = l.serve(route.method, route.requestPath(), body).Code
				}
				assert.Equal(t, statuses["webservice"], statuses["daemon"], "statuses by listener: %v", statuses)
			})
		}
	}
}

// routeKey is a registered method and path template, with any variable
// pattern ({id:[0-9]+}) reduced to its name ({id}).
type routeKey struct {
	method string
	path   string
}

func (k routeKey) String() string { return k.method + " " + k.path }

var (
	routeVarPattern = regexp.MustCompile(`\{(\w+):[^}]*\}`)
	routeVar        = regexp.MustCompile(`\{\w+\}`)
)

// requestPath fills every path variable with the seeded device id.
func (k routeKey) requestPath() string {
	return routeVar.ReplaceAllString(k.path, "1")
}

// bodyMethods are the methods whose handlers decode a request body.
var bodyMethods = map[string]bool{
	http.MethodPost:  true,
	http.MethodPut:   true,
	http.MethodPatch: true,
}

// sharedBodyRoutes returns the body-bearing routes every listener registers.
func sharedBodyRoutes(t *testing.T) []routeKey {
	t.Helper()

	seen := map[routeKey]int{}
	for _, build := range deviceListenerBuilders {
		for key := range registeredRoutes(t, build(t).router) {
			seen[key]++
		}
	}
	var shared []routeKey
	for key, n := range seen {
		if n == len(deviceListenerBuilders) && bodyMethods[key.method] {
			shared = append(shared, key)
		}
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i].String() < shared[j].String() })
	return shared
}

// registeredRoutes walks a router and returns every method and path it
// serves. Subrouter mounts carry a path but no method and are not routes.
func registeredRoutes(t *testing.T, r *mux.Router) map[routeKey]bool {
	t.Helper()

	routes := map[routeKey]bool{}
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, pathErr := route.GetPathTemplate()
		methods, methodErr := route.GetMethods()
		if pathErr != nil || methodErr != nil {
			return nil
		}
		for _, method := range methods {
			routes[routeKey{method, routeVarPattern.ReplaceAllString(path, "{$1}")}] = true
		}
		return nil
	})
	require.NoError(t, err)
	return routes
}

func TestRegisteredRoutes_NormalisesVariablePatterns(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/a/{id:[0-9]+}", http.NotFound).Methods(http.MethodPut)
	r.PathPrefix("/mount").Subrouter().HandleFunc("/b", http.NotFound).Methods(http.MethodPost, http.MethodGet)

	assert.Equal(t, map[routeKey]bool{
		{http.MethodPut, "/a/{id}"}:   true,
		{http.MethodPost, "/mount/b"}: true,
		{http.MethodGet, "/mount/b"}:  true,
	}, registeredRoutes(t, r))
	assert.Equal(t, "/a/1/b/1", routeKey{http.MethodPut, "/a/{id}/b/{x}"}.requestPath())
}

func TestRegisteredRoutes_SkipsMethodlessMounts(t *testing.T) {
	r := mux.NewRouter()
	r.PathPrefix("/mount").Subrouter()
	r.HandleFunc("/any", http.NotFound)

	assert.Empty(t, registeredRoutes(t, r), "a route without a method is not a contract to compare")
}
