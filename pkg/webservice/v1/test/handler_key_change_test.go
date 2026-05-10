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

//go:build integration

package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	"github.com/stretchr/testify/assert"
)

func TestKeyChangeHandler(t *testing.T) {

	// Get the ACME service from the registry
	acmeService := RestServiceRegistry.ACMERestService()
	assert.NotNil(t, acmeService, "ACME service should be configured")
	acmeRouter := router.NewACMERouter(acmeService)

	// Create a new router and register the ACME routes
	// ACMERouter.RegisterRoutes creates a /acme subrouter
	r := mux.NewRouter()
	acmeRouter.RegisterRoutes(r)

	acmeURL := "https://localhost:8443/api/v1/acme/account/16268186706719120207"

	// Define the key-change request body
	keyChangeRequest := trustedca.ACMEKeyChangeRequest{
		AccountURL: acmeURL,
	}

	// Convert the request body to JSON
	requestBodyBytes, err := json.Marshal(keyChangeRequest)
	assert.NoError(t, err)

	// Create a new HTTP request for the key-change endpoint
	// Note: The ACMERouter creates routes under /acme, not /api/v1/acme
	req, err := http.NewRequest("POST", "/acme/key-change", bytes.NewBuffer(requestBodyBytes))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/jose+json")

	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Call the router with the request
	r.ServeHTTP(rr, req)

	// The handler expects a JWS-signed request, so without proper signing
	// it will return an error. We're just testing that the route exists
	// and the handler is reachable.
	// Status code depends on the handler implementation - it may return
	// 400 (Bad Request) or 401 (Unauthorized) due to missing/invalid JWS
	assert.NotEqual(t, http.StatusNotFound, rr.Code, "Route should exist")
	t.Logf("Response status: %d", rr.Code)
	t.Logf("Response body: %s", rr.Body.String())
}
