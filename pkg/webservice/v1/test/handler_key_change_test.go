package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	"github.com/stretchr/testify/assert"
)

func TestKeyChangeHandler(t *testing.T) {

	// Set up a mock ACME service
	// mockService := &MockACMEService{}
	acmeRouter := router.NewACMERouter(RestServiceRegistry.ACMERestService())

	// Create a new router and register the key-change endpoint
	r := mux.NewRouter()
	acmeRouter.RegisterRoutes(r)

	acmeURL := "https://localhost:8443/api/v1/acme/account/16268186706719120207"

	// Define the key-change request body
	keyChangeRequest := acme.KeyChangeRequest{
		AccountURL: acmeURL,
		OldKey:     "mock-old-key",
		NewKey:     "mock-new-key",
	}

	// Convert the request body to JSON
	requestBodyBytes, err := json.Marshal(keyChangeRequest)
	assert.NoError(t, err)

	// Create a new HTTP request for the key-change endpoint
	req, err := http.NewRequest("POST", "/api/v1/acme/key-change", bytes.NewBuffer(requestBodyBytes))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Call the router with the request
	r.ServeHTTP(rr, req)

	// Check the status code is 200 OK
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check that the response contains the expected success message
	expectedResponse := `{"message": "Key updated successfully"}`
	assert.JSONEq(t, expectedResponse, rr.Body.String())
}
