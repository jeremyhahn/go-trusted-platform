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

package push

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Client handles pushing attestation manifests to remote targets.
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
	closed     atomic.Bool
}

// ClientOption configures the push client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	tlsConfig  *tls.Config
	httpClient *http.Client
	rootCAs    *x509.CertPool
}

// WithTLSConfig sets a custom TLS configuration.
func WithTLSConfig(cfg *tls.Config) ClientOption {
	return func(o *clientOptions) {
		o.tlsConfig = cfg
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = client
	}
}

// WithRootCAs anchors the default HTTP transport to the given CA pool instead
// of the operating-system trust store. Ignored when WithHTTPClient or
// WithTLSConfig is also provided (those options supply their own TLS config).
// Pass a nil pool to restore system-roots behavior.
func WithRootCAs(pool *x509.CertPool) ClientOption {
	return func(o *clientOptions) {
		o.rootCAs = pool
	}
}

// NewClient creates a new push client.
func NewClient(config *ClientConfig, opts ...ClientOption) (*Client, error) {
	if config == nil {
		return nil, ErrInvalidConfig{Field: "config", Reason: "cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	options := &clientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	var httpClient *http.Client
	if options.httpClient != nil {
		httpClient = options.httpClient
	} else {
		tlsConfig := options.tlsConfig
		if tlsConfig == nil {
			tlsConfig = config.TLSConfig
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    options.rootCAs, // nil → system roots
			}
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        config.MaxIdleConns,
			MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
			IdleConnTimeout:     config.IdleConnTimeout,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true,
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   config.DefaultTimeout,
		}
	}

	c := &Client{
		config:     config,
		httpClient: httpClient,
	}

	return c, nil
}

// Push sends a manifest to a single target with retry logic.
func (c *Client) Push(ctx context.Context, target *PushTarget, request *PushRequest) (*PushResult, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed{}
	}

	if target == nil {
		return nil, ErrInvalidTarget{Reason: "target cannot be nil"}
	}

	if err := target.Validate(); err != nil {
		return nil, err
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	result := &PushResult{
		TargetID:  target.ID,
		Endpoint:  target.Endpoint,
		Status:    PushStatusPending,
		StartedAt: time.Now(),
		Metadata:  make(map[string]string),
	}

	if !target.Enabled {
		result.Status = PushStatusSkipped
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	retry := c.config.Retry
	if retry == nil {
		retry = DefaultRetryConfig()
	}

	var lastErr error
	retriesExhausted := false
	for attempt := 1; attempt <= retry.MaxAttempts; attempt++ {
		result.Attempts = attempt
		result.Status = PushStatusInFlight

		select {
		case <-ctx.Done():
			result.Status = PushStatusCanceled
			result.Error = ErrContextCanceled{Operation: "push"}
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			return result, result.Error
		default:
		}

		var pushErr error
		switch target.Transport {
		case TransportHTTP:
			pushErr = c.pushHTTP(ctx, target, request, result)
		case TransportGRPC:
			pushErr = c.pushGRPC(ctx, target, request, result)
		default:
			pushErr = ErrTransportNotSupported{Transport: target.Transport.String()}
		}

		if pushErr == nil {
			result.Status = PushStatusSuccess
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			return result, nil
		}

		lastErr = pushErr
		result.Status = PushStatusRetrying

		// Check if we should retry
		if attempt >= retry.MaxAttempts {
			retriesExhausted = true
			break
		}

		// Check if the error is retryable
		if !c.isRetryable(pushErr, result.StatusCode, retry) {
			break
		}

		// Calculate backoff
		backoff := retry.CalculateBackoff(attempt)
		select {
		case <-ctx.Done():
			result.Status = PushStatusCanceled
			result.Error = ErrContextCanceled{Operation: "push retry"}
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			return result, result.Error
		case <-time.After(backoff):
		}
	}

	result.Status = PushStatusFailed
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	// If we exhausted all retries, wrap the error
	if retriesExhausted {
		result.Error = ErrRetryExhausted{
			TargetID:    target.ID,
			Endpoint:    target.Endpoint,
			Attempts:    result.Attempts,
			MaxAttempts: retry.MaxAttempts,
			LastError:   lastErr,
		}
	} else {
		// Non-retryable error, return it directly
		result.Error = lastErr
	}

	return result, result.Error
}

// PushBatch sends a manifest to multiple targets concurrently.
func (c *Client) PushBatch(ctx context.Context, targets []*PushTarget, request *PushRequest) (*PushBatchResult, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed{}
	}

	if len(targets) == 0 {
		return nil, ErrNoTargetsConfigured{}
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	batchResult := &PushBatchResult{
		ManifestID:   request.ManifestID,
		Results:      make([]*PushResult, 0, len(targets)),
		StartedAt:    time.Now(),
		TotalTargets: len(targets),
	}

	type resultPair struct {
		result *PushResult
		err    error
	}

	resultChan := make(chan resultPair, len(targets))

	for _, target := range targets {
		go func(t *PushTarget) {
			result, err := c.Push(ctx, t, request)
			resultChan <- resultPair{result: result, err: err}
		}(target)
	}

	for i := 0; i < len(targets); i++ {
		pair := <-resultChan
		if pair.result != nil {
			batchResult.Results = append(batchResult.Results, pair.result)
			switch pair.result.Status {
			case PushStatusSuccess:
				batchResult.SuccessCount++
			case PushStatusFailed:
				batchResult.FailureCount++
			case PushStatusSkipped:
				batchResult.SkippedCount++
			}
		}
	}

	batchResult.CompletedAt = time.Now()
	batchResult.Duration = batchResult.CompletedAt.Sub(batchResult.StartedAt)

	return batchResult, nil
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	if c.httpClient != nil {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}

	return nil
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	return c.closed.Load()
}

// pushHTTP performs an HTTP push operation.
func (c *Client) pushHTTP(ctx context.Context, target *PushTarget, request *PushRequest, result *PushResult) error {
	timeout := target.Timeout
	if timeout == 0 {
		timeout = c.config.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.Endpoint, bytes.NewReader(request.Payload))
	if err != nil {
		return ErrPushFailed{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   "failed to create request",
			Cause:    err,
		}
	}

	req.Header.Set("Content-Type", request.ContentType)
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	// Add custom headers
	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	// Add authentication
	if err := c.applyAuth(req, target.Auth); err != nil {
		return err
	}

	result.BytesSent = int64(len(request.Payload))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ErrContextCanceled{Operation: "HTTP request"}
		}
		return ErrTargetUnreachable{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   "connection failed",
			Cause:    err,
		}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Debug("failed to close response body", "error", cerr)
		}
	}()

	result.StatusCode = resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return ErrPushFailed{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   "failed to read response",
			Cause:    err,
		}
	}
	result.Response = body

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrAuthFailed{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   string(body),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrInvalidResponse{
			StatusCode: resp.StatusCode,
			Body:       string(body),
			Reason:     "non-success status code",
		}
	}

	return nil
}

// pushGRPC performs a gRPC push operation.
func (c *Client) pushGRPC(ctx context.Context, target *PushTarget, request *PushRequest, result *PushResult) error {
	timeout := target.Timeout
	if timeout == 0 {
		timeout = c.config.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialOpts []grpc.DialOption

	// Configure TLS
	if target.Auth != nil && target.Auth.TLSConfig != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(target.Auth.TLSConfig)))
	} else if target.Auth != nil && target.Auth.CACert != "" {
		tlsConfig, err := c.buildTLSConfig(target.Auth)
		if err != nil {
			return err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(target.Endpoint, dialOpts...)
	if err != nil {
		return ErrTargetUnreachable{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   "failed to connect",
			Cause:    err,
		}
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			slog.Debug("failed to close gRPC connection", "error", cerr)
		}
	}()

	// Add auth metadata
	if target.Auth != nil && target.Auth.Token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+target.Auth.Token)
	}

	// For gRPC, we use a generic unary call since we don't have the proto definitions
	// In practice, this would use the actual attestation service client
	result.BytesSent = int64(len(request.Payload))

	// Use raw codec call for generic push
	var response []byte
	err = conn.Invoke(ctx, "/attestation.PushService/Push", request.Payload, &response)
	if err != nil {
		return ErrPushFailed{
			TargetID: target.ID,
			Endpoint: target.Endpoint,
			Reason:   "gRPC call failed",
			Cause:    err,
		}
	}

	result.Response = response
	return nil
}

// applyAuth applies authentication to an HTTP request.
func (c *Client) applyAuth(req *http.Request, auth *AuthConfig) error {
	if auth == nil {
		return nil
	}

	switch auth.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case "basic":
		credentials := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		req.Header.Set("Authorization", "Basic "+credentials)
	case "mtls":
		// mTLS is configured at transport level, nothing to do here
	case "":
		// No auth configured
	default:
		return ErrAuthFailed{Reason: "unsupported auth type: " + auth.Type}
	}

	return nil
}

// buildTLSConfig builds a TLS configuration from auth config.
func (c *Client) buildTLSConfig(auth *AuthConfig) (*tls.Config, error) {
	if auth.TLSConfig != nil {
		return auth.TLSConfig, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if auth.ClientCert != "" && auth.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(auth.ClientCert, auth.ClientKey)
		if err != nil {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to load client certificate",
				Cause:  err,
			}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if auth.CACert != "" {
		caCert, err := os.ReadFile(auth.CACert)
		if err != nil {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to read CA certificate",
				Cause:  err,
			}
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to parse CA certificate",
			}
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// isRetryable determines if an error should trigger a retry.
func (c *Client) isRetryable(err error, statusCode int, retry *RetryConfig) bool {
	// Network errors are usually retryable
	if _, ok := err.(ErrTargetUnreachable); ok {
		return true
	}

	// Don't retry auth failures
	if _, ok := err.(ErrAuthFailed); ok {
		return false
	}

	// Don't retry invalid targets
	if _, ok := err.(ErrInvalidTarget); ok {
		return false
	}

	// Don't retry invalid responses (client errors)
	if resp, ok := err.(ErrInvalidResponse); ok {
		// Only retry server errors, not client errors
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return false
		}
	}

	// Check status codes from result
	if statusCode > 0 {
		return retry.IsRetryableStatus(statusCode)
	}

	// Default to retryable for unknown errors
	return true
}

// LoadTLSConfigFromFiles creates a TLS config from certificate files.
func LoadTLSConfigFromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to load client certificate",
				Cause:  err,
			}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to read CA certificate",
				Cause:  err,
			}
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrTLSConfigFailed{
				Reason: "failed to parse CA certificate",
			}
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}
