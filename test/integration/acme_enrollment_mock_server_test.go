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
// +build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/stretchr/testify/require"
)

// mockProvisioningServer wraps an http.Server for testing
type mockProvisioningServer struct {
	server   *http.Server
	listener net.Listener
	URL      string
}

func createProvisioningClient(t *testing.T, env *testEnvironment) *provisioning.Client {
	t.Helper()

	// Create CA cert pool
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(env.caCert)

	// Create mock HTTP server for provisioning endpoints
	mockServer := createMockProvisioningServer(t, env)

	config := &provisioning.ClientConfig{
		ServerURL:   mockServer.URL,
		Certificate: env.deviceCertificate,
		PrivateKey:  env.devicePrivateKey,
		CACertPool:  caCertPool,
		Timeout:     30 * time.Second,
	}

	client, err := provisioning.NewClient(config, env.logger)
	require.NoError(t, err, "Failed to create provisioning client")

	return client
}

func createMockProvisioningServer(t *testing.T, env *testEnvironment) *mockProvisioningServer {
	t.Helper()

	mux := http.NewServeMux()

	// GET /api/v1/device/profile
	mux.HandleFunc("/api/v1/device/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract serial from client certificate
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		serial := r.TLS.PeerCertificates[0].Subject.SerialNumber

		response := &provisioning.ProfileResponse{
			SerialNumber: serial,
			AdmittedNetwork: provisioning.NetworkConfig{
				VLAN:    productionVLAN,
				UseDHCP: true,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// POST /api/v1/device/activate
	mux.HandleFunc("/api/v1/device/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract serial from client certificate
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		serial := r.TLS.PeerCertificates[0].Subject.SerialNumber

		// Activate the device: precheck reserves the pending activation
		// as an immutable plan, and activation consumes exactly that plan.
		plan, err := env.enrollmentHook.PrecheckActivation(serial)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := env.enrollmentHook.ActivateDevice(plan); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		env.enrollmentHook.FinalizeActivation(plan)

		response := &provisioning.ActivateResponse{
			Status:         "activated",
			VLAN:           productionVLAN,
			TransitionedAt: time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Create listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to create listener")

	// Configure TLS
	tlsCert := tls.Certificate{
		Certificate: [][]byte{env.caCert.Raw},
		PrivateKey:  env.caKey,
		Leaf:        env.caCert,
	}

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
	}

	// Start server in background. The listener is already bound, so
	// clients that connect before ServeTLS runs wait in its accept queue.
	go func() {
		server.ServeTLS(listener, "", "")
	}()

	mockServer := &mockProvisioningServer{
		server:   server,
		listener: listener,
		URL:      fmt.Sprintf("https://%s", listener.Addr().String()),
	}

	// Register cleanup
	env.addCleanup(func() {
		server.Close()
		listener.Close()
	})

	return mockServer
}
