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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	devicehandler "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/require"
)

// provisioningServer wraps the TLS http.Server serving the device routes.
type provisioningServer struct {
	server   *http.Server
	listener net.Listener
	URL      string
}

func createProvisioningClient(t *testing.T, env *testEnvironment) *provisioning.Client {
	t.Helper()

	// Create CA cert pool
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(env.caCert)

	server := createProvisioningServer(t, env)

	config := &provisioning.ClientConfig{
		ServerURL:   server.URL,
		Certificate: env.deviceCertificate,
		PrivateKey:  env.devicePrivateKey,
		CACertPool:  caCertPool,
		Timeout:     30 * time.Second,
	}

	client, err := provisioning.NewClient(config, env.logger)
	require.NoError(t, err, "Failed to create provisioning client")

	return client
}

// createProvisioningServer serves the device routes through the product's
// device handler (pkg/webservice/v1/device) on the suite's enrollment hook,
// so the statuses the suite asserts are the ones platformd answers
// (docs/sdn/provisioning.md, "POST /api/v1/device/activate").
func createProvisioningServer(t *testing.T, env *testEnvironment) *provisioningServer {
	t.Helper()

	writer := response.NewResponseWriter(env.logger, nil)
	handler := devicehandler.NewHandler(env.logger, writer, env.enrollmentHook,
		v1.NewEnrollmentHookProfileService(env.enrollmentHook))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/device/profile", withDeviceSerial(handler.GetProfile))
	mux.HandleFunc("POST /api/v1/device/activate", withDeviceSerial(handler.Activate))

	// Create listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to create listener")

	// Configure TLS with a server leaf the client can verify against the CA
	// for the address it dials.
	tlsCert := issueProvisioningServerCertificate(t, env)

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

	served := &provisioningServer{
		server:   server,
		listener: listener,
		URL:      fmt.Sprintf("https://%s", listener.Addr().String()),
	}

	// Register cleanup
	env.addCleanup(func() {
		server.Close()
		listener.Close()
	})

	return served
}

// withDeviceSerial puts the client certificate's subject serialNumber —
// the identity the enrollment hook keys the pending activation on — in the
// request context under the key the device handler reads.
func withDeviceSerial(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}
		serial := r.TLS.PeerCertificates[0].Subject.SerialNumber
		ctx := context.WithValue(r.Context(), devicehandler.ContextKeyDeviceSerial, serial)
		next(w, r.WithContext(ctx))
	}
}

// issueProvisioningServerCertificate issues the provisioning server's TLS leaf
// from the test CA, naming the loopback address the server listens on.
func issueProvisioningServerCertificate(t *testing.T, env *testEnvironment) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate provisioning server key")

	template := &x509.Certificate{
		SerialNumber: env.nextSerial(),
		Subject:      pkix.Name{CommonName: "provisioning.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(certificateValidTime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, env.caCert, key.Public(), env.caKey)
	require.NoError(t, err, "issue provisioning server certificate")

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse provisioning server certificate")

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}
