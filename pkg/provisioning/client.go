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

// Package provisioning provides a client for device provisioning operations.
// After ACME enrollment completes and the device receives its IDevID certificate,
// this client uses mTLS to fetch the device profile and signal activation readiness.
//
// The flow is:
//  1. Device enrolls via ACME (enroll-01 challenge) and receives IDevID
//  2. Device creates mTLS client using IDevID
//  3. Device fetches profile via GET /api/v1/device/profile
//  4. Device signals ready via POST /api/v1/device/activate
//  5. Server transitions port to trusted VLAN
//  6. Device applies trusted network configuration
package provisioning

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Client is a provisioning client that uses mTLS with IDevID certificate
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
	logger     *logging.Logger
}

// NewClient creates a new provisioning client with the given configuration.
// The client uses mTLS with the IDevID certificate to authenticate to the server.
func NewClient(config *ClientConfig, logger *logging.Logger) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required: %w", ErrInvalidResponse)
	}

	if config.Certificate == nil {
		return nil, ErrMissingCertificate
	}

	if config.PrivateKey == nil {
		return nil, ErrMissingPrivateKey
	}

	if config.CACertPool == nil {
		return nil, ErrMissingCABundle
	}

	// Create TLS certificate from IDevID
	tlsCert := tls.Certificate{
		Certificate: [][]byte{config.Certificate.Raw},
		PrivateKey:  config.PrivateKey,
		Leaf:        config.Certificate,
	}

	// Configure TLS with mTLS — TLS 1.3 minimum enforced.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      config.CACertPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Create HTTP client with mTLS transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
		logger:     logger,
	}, nil
}

// FetchProfile retrieves the device profile from the provisioning server.
// The server identifies the device from the client certificate presented in mTLS.
func (c *Client) FetchProfile(ctx context.Context) (*ProfileResponse, error) {
	url := fmt.Sprintf("%s/api/v1/device/profile", c.config.ServerURL)

	c.logger.Info("Fetching device profile via mTLS", "url", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrProfileFetchFailed, err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error(err, "context", "profile fetch request failed")
		return nil, fmt.Errorf("%w: request failed: %v", ErrConnectionFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Errorf("profile fetch returned error: status=%d, body=%s",
			resp.StatusCode, string(body))
		return nil, fmt.Errorf("%w: server returned status %d", ErrServerError, resp.StatusCode)
	}

	var profile ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrInvalidResponse, err)
	}

	c.logger.Info("Device profile fetched successfully",
		"serial", profile.SerialNumber,
		"vlan", profile.TrustedNetwork.VLAN,
		"useDHCP", profile.TrustedNetwork.UseDHCP)

	return &profile, nil
}

// Activate signals the server that the device is ready for network transition.
// The server will transition the device's port to the trusted VLAN.
func (c *Client) Activate(ctx context.Context) (*ActivateResponse, error) {
	url := fmt.Sprintf("%s/api/v1/device/activate", c.config.ServerURL)

	c.logger.Info("Signaling device activation via mTLS", "url", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrActivationFailed, err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error(err, "context", "activation request failed")
		return nil, fmt.Errorf("%w: request failed: %v", ErrConnectionFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Errorf("activation returned error: status=%d, body=%s",
			resp.StatusCode, string(body))
		return nil, fmt.Errorf("%w: server returned status %d", ErrServerError, resp.StatusCode)
	}

	var activateResp ActivateResponse
	if err := json.NewDecoder(resp.Body).Decode(&activateResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrInvalidResponse, err)
	}

	c.logger.Info("Device activation successful",
		"status", activateResp.Status,
		"vlan", activateResp.VLAN,
		"transitionedAt", activateResp.TransitionedAt)

	return &activateResp, nil
}

// FetchProfileAndActivate performs the complete provisioning flow:
// 1. Fetches the device profile via mTLS
// 2. Signals activation readiness to the server
// 3. Returns the profile for network configuration
//
// After this call returns, the server has transitioned the port to the trusted VLAN.
// The caller should then apply the trusted network configuration.
func (c *Client) FetchProfileAndActivate(ctx context.Context) (*ProfileResponse, *ActivateResponse, error) {
	// Step 1: Fetch profile
	profile, err := c.FetchProfile(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("profile fetch failed: %w", err)
	}

	// Step 2: Activate (signal ready for network transition)
	activateResp, err := c.Activate(ctx)
	if err != nil {
		return profile, nil, fmt.Errorf("activation failed: %w", err)
	}

	c.logger.Info("Provisioning flow complete",
		"serial", profile.SerialNumber,
		"trustedVLAN", profile.TrustedNetwork.VLAN,
		"activationStatus", activateResp.Status)

	return profile, activateResp, nil
}

// Close releases any resources held by the client.
func (c *Client) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}
