package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"

	"github.com/stretchr/testify/assert"
)

// type MockTransport struct{}

// func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
// 	return &http.Response{
// 		StatusCode: http.StatusOK,
// 		Body:       io.NopCloser(strings.NewReader(`{"message": "mock response"}`)),
// 		Header:     make(http.Header),
// 	}, nil
// }

func TestHttpClientWithTable(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
	}{
		{"Success", http.StatusOK, `{"message": "success"}`, false},
		{"NotFound", http.StatusNotFound, `{"message": "not found"}`, true},
		{"InternalServerError", http.StatusInternalServerError, `{"message": "error"}`, true},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			// server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 	w.WriteHeader(tt.statusCode)
			// 	w.Write([]byte(tt.responseBody))
			// }))

			acmeRestService := RestServiceRegistry.ACMERestService()

			server := httptest.NewServer(http.HandlerFunc(acmeRestService.NewAccountHandler))
			defer server.Close()

			// client := &http.Client{
			// 	Transport: &MockTransport{},
			// }
			client := server.Client()

			acmeClient, err := acme.NewClient(acme.ClientConfig{}, client, nil, nil, nil)
			assert.Nil(t, err)

			_, err = acmeClient.RegisterAccount()
			assert.Nil(t, err)

			//req, _ := http.NewRequest("GET", server.URL, nil)

			//resp, err := client.Do(req)
			if tt.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				return
			}

			// if resp.StatusCode != tt.statusCode {
			// 	t.Errorf("Expected status %v, got %v", tt.statusCode, resp.StatusCode)
			// }

			assert.Nil(t, err)
		})
	}
}
