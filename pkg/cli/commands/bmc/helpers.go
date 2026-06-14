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

package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

// bmcBasePath is the base path for BMC API endpoints.
const bmcBasePath = "/api/v1/bmc"

// envPlatformCACert is the environment variable consulted for the platformd
// CA bundle when no --ca-cert flag is supplied.
const envPlatformCACert = "PLATFORM_CA_CERT"

// envPlatformClientCert and envPlatformClientKey are consulted for the mutual
// TLS client certificate/key when the corresponding flags are not supplied.
const (
	envPlatformClientCert = "PLATFORM_CLIENT_CERT"
	envPlatformClientKey  = "PLATFORM_CLIENT_KEY"
)

// webServiceEnvelope is the server-side WebServiceResponse wrapper that
// surrounds every payload returned by the daemon's REST API. The daemon always
// sets Code to a non-zero HTTP status (200, 201, 400, etc.).
type webServiceEnvelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

// newBMCHTTPClient builds an HTTP client for the daemon-mode REST path. A CA
// bundle (via --ca-cert or $PLATFORM_CA_CERT) is installed as the trust anchor
// for verifying the platformd TLS certificate; otherwise the system trust
// store is used. A client certificate (via --client-cert/--client-key or
// $PLATFORM_CLIENT_CERT/$PLATFORM_CLIENT_KEY) is presented for mutual TLS when
// platformd requires one. InsecureSkipVerify is never set.
func newBMCHTTPClient(flags *bmcFlags) (*http.Client, error) {
	var tlsConfig *tls.Config

	caPath := flags.caCert
	if caPath == "" {
		caPath = os.Getenv(envPlatformCACert)
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, ErrCABundleLoadFailed{Path: caPath, Cause: err}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, ErrCABundleLoadFailed{Path: caPath}
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}

	// Present a client certificate for mutual TLS when configured. platformd
	// may require a client cert (--enable-mtls); without one the handshake
	// fails with "certificate required".
	clientCert, clientKey := flags.clientCert, flags.clientKey
	if clientCert == "" {
		clientCert = os.Getenv(envPlatformClientCert)
	}
	if clientKey == "" {
		clientKey = os.Getenv(envPlatformClientKey)
	}
	if clientCert != "" && clientKey != "" {
		cert, certErr := tls.LoadX509KeyPair(clientCert, clientKey)
		if certErr != nil {
			return nil, ErrClientCertLoadFailed{CertPath: clientCert, KeyPath: clientKey, Cause: certErr}
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if tlsConfig == nil {
		return &http.Client{}, nil
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// validateBMCFlags validates that all required BMC flags are set.
func validateBMCFlags(flags *bmcFlags) error {
	if flags.serverURL == "" {
		return ErrServerURLRequired{}
	}
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	return nil
}

// buildURL constructs a BMC API URL from the server URL, profile ID, and path segments.
func buildURL(serverURL, profileID string, segments ...string) string {
	base := strings.TrimRight(serverURL, "/") + bmcBasePath + "/" + profileID
	for _, seg := range segments {
		base += "/" + seg
	}
	return base
}

// decodeResponse decodes the JSON body into dest. When the body contains a
// daemon WebServiceResponse envelope (identified by a non-zero Code field), the
// Payload is extracted and decoded. Otherwise the body is decoded directly,
// which keeps unit-test HTTP servers that return raw JSON working without
// modification.
func decodeResponse(body []byte, dest interface{}) error {
	var env webServiceEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Code != 0 {
		if env.Error != "" {
			return ErrUnexpectedStatus{StatusCode: env.Code, Body: env.Error}
		}
		if len(env.Payload) > 0 {
			if err := json.Unmarshal(env.Payload, dest); err != nil {
				return ErrResponseDecodeFailed{Cause: err}
			}
		}
		return nil
	}
	// Not an envelope; decode the body directly.
	if err := json.Unmarshal(body, dest); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}
	return nil
}

// doGet performs an HTTP GET request and decodes the JSON response payload into dest.
// The daemon wraps every response in a WebServiceResponse envelope; this
// function unwraps it transparently.
func doGet(ctx context.Context, client *http.Client, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	if resp.StatusCode != http.StatusOK {
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	if dest == nil || len(body) == 0 {
		return nil
	}

	return decodeResponse(body, dest)
}

// doPost performs an HTTP POST request with a JSON body and decodes the
// response payload into dest. The daemon wraps every response in a
// WebServiceResponse envelope; this function unwraps it transparently.
func doPost(ctx context.Context, client *http.Client, url string, payload interface{}, dest interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return ErrRequestEncodeFailed{Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	if resp.StatusCode != http.StatusOK {
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	if dest == nil || len(respBody) == 0 {
		return nil
	}

	return decodeResponse(respBody, dest)
}

// doDelete performs an HTTP DELETE request and decodes the response payload
// into dest. The daemon wraps every response in a WebServiceResponse envelope;
// this function unwraps it transparently.
func doDelete(ctx context.Context, client *http.Client, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return ErrRequestBuildFailed{Cause: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ErrRequestFailed{URL: url, Cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}

	if resp.StatusCode != http.StatusOK {
		return ErrUnexpectedStatus{StatusCode: resp.StatusCode, Body: string(body)}
	}

	if dest == nil || len(body) == 0 {
		return nil
	}

	return decodeResponse(body, dest)
}

// validPowerActions is the set of valid power action strings.
var validPowerActions = map[string]PowerAction{
	"on":    PowerActionOn,
	"off":   PowerActionOff,
	"reset": PowerActionReset,
	"cycle": PowerActionCycle,
}

// validBootDevices is the set of valid boot device strings.
var validBootDevices = map[string]bool{
	"pxe":   true,
	"disk":  true,
	"cdrom": true,
	"bios":  true,
}

// validRoles maps CLI role names to SDK privilege values.
var validRoles = map[string]string{
	"administrator": "ADMINISTRATOR",
	"operator":      "OPERATOR",
	"user":          "USER",
	"callback":      "CALLBACK",
	"no-access":     "NO_ACCESS",
}

// encodeJSON encodes a value as JSON to the given writer.
func encodeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ErrResponseDecodeFailed{Cause: err}
	}
	return nil
}
