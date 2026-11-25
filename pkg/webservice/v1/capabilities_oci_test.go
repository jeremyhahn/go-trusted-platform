// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// TestCapabilities_ListsRecordedRootRoutes checks that buildCapabilities
// lists the root routes the caller recorded as enabled routes with no
// owning service (#2063).
func TestCapabilities_ListsRecordedRootRoutes(t *testing.T) {
	root := mux.NewRouter()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	rootRoutes := recordNewRoutes(root, func() {
		root.HandleFunc("/v2/{name:.+}/manifests/{reference}", ok).Methods(http.MethodDelete)
	})

	got := buildCapabilities(mux.NewRouter(), "", nil, nil, nil, rootRoutes)

	require.Len(t, got.Capabilities, 1)
	c := got.Capabilities[0]
	require.Equal(t, "DELETE /v2/{name:.+}/manifests/{reference}", c.Op)
	require.Equal(t, CapabilityKindRoute, c.Kind)
	require.True(t, c.Enabled)
	require.Empty(t, c.Service)
	require.Empty(t, c.Reason)
	require.Equal(t, 1, got.Total)
	require.Equal(t, 1, got.Enabled)
}

// TestRegisterRootRoutes_CapabilitiesListTheOCIRoutes checks that the OCI
// Distribution routes RegisterRootRoutes mounts on the root router are
// recorded for the capabilities listing, and the health probes are not
// (#2063).
func TestRegisterRootRoutes_CapabilitiesListTheOCIRoutes(t *testing.T) {
	registry := &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		ociDistBackend: &stubOCIDistBackend{},
	}
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry.responseWriter = respWriter
	registry.iamClient = &probeIAM{}
	registry.pepClient = &probePEP{}
	registry.tenantID = "system"

	v1Router, isRouter := NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter).(*Router)
	require.True(t, isRouter)
	root := mux.NewRouter()
	require.NoError(t, v1Router.RegisterRootRoutes(root))

	got := buildCapabilities(mux.NewRouter(), "", nil, nil, nil, v1Router.rootRoutes)

	byOp := map[string]Capability{}
	for _, c := range got.Capabilities {
		byOp[c.Op] = c
		require.True(t, strings.HasPrefix(c.Op, "GET /v2") || strings.Contains(c.Op, " /v2"),
			"unexpected op %q", c.Op)
	}
	for _, op := range []string{
		"GET /v2/_catalog",
		"GET /v2/{name:.+}/tags/list",
		"GET /v2/{name:.+}/manifests/{reference}",
		"PUT /v2/{name:.+}/manifests/{reference}",
		"DELETE /v2/{name:.+}/manifests/{reference}",
		"POST /v2/{name:.+}/blobs/uploads/",
		"GET /v2/{name:.+}/blobs/{digest}",
	} {
		c, found := byOp[op]
		require.True(t, found, "missing op %q", op)
		require.True(t, c.Enabled, "op %q disabled", op)
	}
}
