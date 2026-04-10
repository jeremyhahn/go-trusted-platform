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
	"crypto/tls"
	"net/url"
	"time"
)

// TransportType represents the transport protocol for pushing attestations.
type TransportType string

// Supported transport types.
const (
	TransportHTTP TransportType = "http"
	TransportGRPC TransportType = "grpc"
)

// String returns the string representation of TransportType.
func (t TransportType) String() string {
	return string(t)
}

// IsValid returns true if the transport type is supported.
func (t TransportType) IsValid() bool {
	switch t {
	case TransportHTTP, TransportGRPC:
		return true
	default:
		return false
	}
}

// TriggerType represents when a push operation should be triggered.
type TriggerType string

// Supported trigger types.
const (
	TriggerPeriodic TriggerType = "periodic"
	TriggerOnChange TriggerType = "on-change"
	TriggerManual   TriggerType = "manual"
)

// String returns the string representation of TriggerType.
func (t TriggerType) String() string {
	return string(t)
}

// IsValid returns true if the trigger type is valid.
func (t TriggerType) IsValid() bool {
	switch t {
	case TriggerPeriodic, TriggerOnChange, TriggerManual:
		return true
	default:
		return false
	}
}

// PushStatus represents the status of a push operation.
type PushStatus string

// Push status constants.
const (
	PushStatusPending  PushStatus = "pending"
	PushStatusInFlight PushStatus = "in-flight"
	PushStatusSuccess  PushStatus = "success"
	PushStatusFailed   PushStatus = "failed"
	PushStatusRetrying PushStatus = "retrying"
	PushStatusCanceled PushStatus = "canceled"
	PushStatusSkipped  PushStatus = "skipped"
)

// String returns the string representation of PushStatus.
func (s PushStatus) String() string {
	return string(s)
}

// IsValid returns true if the push status is valid.
func (s PushStatus) IsValid() bool {
	switch s {
	case PushStatusPending, PushStatusInFlight, PushStatusSuccess,
		PushStatusFailed, PushStatusRetrying, PushStatusCanceled, PushStatusSkipped:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if this status represents a final state.
func (s PushStatus) IsTerminal() bool {
	switch s {
	case PushStatusSuccess, PushStatusFailed, PushStatusCanceled, PushStatusSkipped:
		return true
	default:
		return false
	}
}

// AuthConfig contains authentication configuration for a push target.
type AuthConfig struct {
	// Type is the authentication type (bearer, mtls, basic).
	Type string

	// Token is the bearer token for token-based auth.
	Token string

	// Username for basic authentication.
	Username string

	// Password for basic authentication.
	Password string

	// ClientCert is the path to the client certificate for mTLS.
	ClientCert string

	// ClientKey is the path to the client private key for mTLS.
	ClientKey string

	// CACert is the path to the CA certificate for server verification.
	CACert string

	// TLSConfig is a pre-configured TLS configuration.
	TLSConfig *tls.Config
}

// Validate validates the AuthConfig fields.
func (c *AuthConfig) Validate() error {
	if c.Type == "" {
		return nil // No auth configured
	}

	switch c.Type {
	case "bearer":
		if c.Token == "" {
			return ErrInvalidConfig{Field: "Token", Reason: "bearer token cannot be empty"}
		}
	case "basic":
		if c.Username == "" {
			return ErrInvalidConfig{Field: "Username", Reason: "username cannot be empty for basic auth"}
		}
	case "mtls":
		if c.ClientCert == "" {
			return ErrInvalidConfig{Field: "ClientCert", Reason: "client certificate path cannot be empty for mTLS"}
		}
		if c.ClientKey == "" {
			return ErrInvalidConfig{Field: "ClientKey", Reason: "client key path cannot be empty for mTLS"}
		}
	default:
		return ErrInvalidConfig{Field: "Type", Reason: "unsupported auth type: " + c.Type}
	}

	return nil
}

// PushTarget represents a destination endpoint for attestation pushes.
type PushTarget struct {
	// ID is a unique identifier for this target.
	ID string

	// Name is a human-readable name for this target.
	Name string

	// Endpoint is the URL of the target service.
	Endpoint string

	// Transport is the transport protocol to use.
	Transport TransportType

	// Auth contains authentication configuration.
	Auth *AuthConfig

	// Enabled indicates whether this target is active.
	Enabled bool

	// Headers contains additional HTTP headers to include.
	Headers map[string]string

	// Timeout is the request timeout for this target.
	Timeout time.Duration

	// Metadata contains additional target-specific metadata.
	Metadata map[string]string
}

// Validate validates the PushTarget fields.
func (t *PushTarget) Validate() error {
	if t.ID == "" {
		return ErrInvalidTarget{Field: "ID", Reason: "target ID cannot be empty"}
	}

	if t.Endpoint == "" {
		return ErrInvalidTarget{TargetID: t.ID, Field: "Endpoint", Reason: "endpoint cannot be empty"}
	}

	parsedURL, err := url.Parse(t.Endpoint)
	if err != nil {
		return ErrInvalidTarget{TargetID: t.ID, Field: "Endpoint", Reason: "invalid URL: " + err.Error()}
	}

	if parsedURL.Host == "" {
		return ErrInvalidTarget{TargetID: t.ID, Field: "Endpoint", Reason: "endpoint must have a host"}
	}

	if !t.Transport.IsValid() {
		return ErrInvalidTarget{TargetID: t.ID, Field: "Transport", Reason: "invalid transport type"}
	}

	if t.Auth != nil {
		if err := t.Auth.Validate(); err != nil {
			return ErrInvalidTarget{TargetID: t.ID, Field: "Auth", Reason: err.Error()}
		}
	}

	if t.Timeout < 0 {
		return ErrInvalidTarget{TargetID: t.ID, Field: "Timeout", Reason: "timeout cannot be negative"}
	}

	return nil
}

// PushResult represents the outcome of a push operation to a single target.
type PushResult struct {
	// TargetID is the ID of the target this result is for.
	TargetID string

	// Endpoint is the endpoint that was pushed to.
	Endpoint string

	// Status is the push status.
	Status PushStatus

	// StatusCode is the HTTP status code (for HTTP transport).
	StatusCode int

	// Attempts is the number of attempts made.
	Attempts int

	// StartedAt is when the push operation started.
	StartedAt time.Time

	// CompletedAt is when the push operation completed.
	CompletedAt time.Time

	// Duration is the total time taken for the push.
	Duration time.Duration

	// BytesSent is the number of bytes sent.
	BytesSent int64

	// Error contains any error that occurred.
	Error error

	// Response contains the response body from the target.
	Response []byte

	// Metadata contains additional result metadata.
	Metadata map[string]string
}

// Success returns true if the push was successful.
func (r *PushResult) Success() bool {
	return r.Status == PushStatusSuccess
}

// RetryConfig contains configuration for retry logic.
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts.
	MaxAttempts int

	// InitialBackoff is the initial backoff duration.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	MaxBackoff time.Duration

	// BackoffMultiplier is the factor to multiply backoff by after each attempt.
	BackoffMultiplier float64

	// RetryableStatusCodes are HTTP status codes that should trigger a retry.
	RetryableStatusCodes []int
}

// Validate validates the RetryConfig fields.
func (c *RetryConfig) Validate() error {
	if c.MaxAttempts < 1 {
		return ErrInvalidConfig{Field: "MaxAttempts", Reason: "must be at least 1"}
	}

	if c.InitialBackoff <= 0 {
		return ErrInvalidConfig{Field: "InitialBackoff", Reason: "must be positive"}
	}

	if c.MaxBackoff < c.InitialBackoff {
		return ErrInvalidConfig{Field: "MaxBackoff", Reason: "must be >= InitialBackoff"}
	}

	if c.BackoffMultiplier < 1.0 {
		return ErrInvalidConfig{Field: "BackoffMultiplier", Reason: "must be >= 1.0"}
	}

	return nil
}

// DefaultRetryConfig returns a RetryConfig with sensible defaults.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:       3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableStatusCodes: []int{
			408, // Request Timeout
			429, // Too Many Requests
			500, // Internal Server Error
			502, // Bad Gateway
			503, // Service Unavailable
			504, // Gateway Timeout
		},
	}
}

// IsRetryableStatus returns true if the status code should trigger a retry.
func (c *RetryConfig) IsRetryableStatus(statusCode int) bool {
	for _, code := range c.RetryableStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// CalculateBackoff calculates the backoff duration for a given attempt.
func (c *RetryConfig) CalculateBackoff(attempt int) time.Duration {
	if attempt < 1 {
		return c.InitialBackoff
	}

	backoff := c.InitialBackoff
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * c.BackoffMultiplier)
		if backoff > c.MaxBackoff {
			return c.MaxBackoff
		}
	}
	return backoff
}

// PushConfig contains the overall configuration for push operations.
type PushConfig struct {
	// Targets is the list of push targets.
	Targets []*PushTarget

	// Retry contains retry configuration.
	Retry *RetryConfig

	// DefaultTimeout is the default timeout for push operations.
	DefaultTimeout time.Duration

	// DefaultTransport is the default transport type.
	DefaultTransport TransportType

	// TriggerType is when pushes should be triggered.
	TriggerType TriggerType

	// PushInterval is the interval for periodic pushes.
	PushInterval time.Duration

	// MaxConcurrentPushes is the maximum number of concurrent push operations.
	MaxConcurrentPushes int

	// FailFast stops on first target failure if true.
	FailFast bool
}

// Validate validates the PushConfig fields.
func (c *PushConfig) Validate() error {
	if len(c.Targets) == 0 {
		return ErrNoTargetsConfigured{}
	}

	for _, target := range c.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
	}

	if c.Retry != nil {
		if err := c.Retry.Validate(); err != nil {
			return err
		}
	}

	if c.DefaultTimeout < 0 {
		return ErrInvalidConfig{Field: "DefaultTimeout", Reason: "cannot be negative"}
	}

	if c.DefaultTransport != "" && !c.DefaultTransport.IsValid() {
		return ErrInvalidConfig{Field: "DefaultTransport", Reason: "invalid transport type"}
	}

	if c.TriggerType != "" && !c.TriggerType.IsValid() {
		return ErrInvalidConfig{Field: "TriggerType", Reason: "invalid trigger type"}
	}

	if c.TriggerType == TriggerPeriodic && c.PushInterval <= 0 {
		return ErrInvalidConfig{Field: "PushInterval", Reason: "must be positive for periodic triggers"}
	}

	if c.MaxConcurrentPushes < 0 {
		return ErrInvalidConfig{Field: "MaxConcurrentPushes", Reason: "cannot be negative"}
	}

	return nil
}

// DefaultPushConfig returns a PushConfig with sensible defaults.
func DefaultPushConfig() *PushConfig {
	return &PushConfig{
		Targets:             make([]*PushTarget, 0),
		Retry:               DefaultRetryConfig(),
		DefaultTimeout:      30 * time.Second,
		DefaultTransport:    TransportHTTP,
		TriggerType:         TriggerPeriodic,
		PushInterval:        5 * time.Minute,
		MaxConcurrentPushes: 10,
		FailFast:            false,
	}
}

// GetEnabledTargets returns only enabled targets.
func (c *PushConfig) GetEnabledTargets() []*PushTarget {
	enabled := make([]*PushTarget, 0, len(c.Targets))
	for _, t := range c.Targets {
		if t.Enabled {
			enabled = append(enabled, t)
		}
	}
	return enabled
}

// GetTargetByID returns a target by its ID.
func (c *PushConfig) GetTargetByID(id string) *PushTarget {
	for _, t := range c.Targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// ClientConfig contains configuration for the PushClient.
type ClientConfig struct {
	// DefaultTimeout is the default request timeout.
	DefaultTimeout time.Duration

	// TLSConfig is the default TLS configuration.
	TLSConfig *tls.Config

	// UserAgent is the User-Agent header for HTTP requests.
	UserAgent string

	// Retry contains retry configuration.
	Retry *RetryConfig

	// MaxIdleConns is the maximum number of idle connections.
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum number of idle connections per host.
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the timeout for idle connections.
	IdleConnTimeout time.Duration
}

// Validate validates the ClientConfig fields.
func (c *ClientConfig) Validate() error {
	if c.DefaultTimeout < 0 {
		return ErrInvalidConfig{Field: "DefaultTimeout", Reason: "cannot be negative"}
	}

	if c.Retry != nil {
		if err := c.Retry.Validate(); err != nil {
			return err
		}
	}

	if c.MaxIdleConns < 0 {
		return ErrInvalidConfig{Field: "MaxIdleConns", Reason: "cannot be negative"}
	}

	if c.MaxIdleConnsPerHost < 0 {
		return ErrInvalidConfig{Field: "MaxIdleConnsPerHost", Reason: "cannot be negative"}
	}

	if c.IdleConnTimeout < 0 {
		return ErrInvalidConfig{Field: "IdleConnTimeout", Reason: "cannot be negative"}
	}

	return nil
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		DefaultTimeout:      30 * time.Second,
		UserAgent:           "go-trusted-platform/1.0",
		Retry:               DefaultRetryConfig(),
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}

// SchedulerConfig contains configuration for the PushScheduler.
type SchedulerConfig struct {
	// TriggerType is when pushes should be triggered.
	TriggerType TriggerType

	// PushInterval is the interval for periodic pushes.
	PushInterval time.Duration

	// MaxConcurrentPushes is the maximum number of concurrent push operations.
	MaxConcurrentPushes int

	// FailFast stops on first target failure if true.
	FailFast bool

	// OnChangeDebounce is the debounce duration for on-change triggers.
	OnChangeDebounce time.Duration
}

// Validate validates the SchedulerConfig fields.
func (c *SchedulerConfig) Validate() error {
	if !c.TriggerType.IsValid() {
		return ErrInvalidConfig{Field: "TriggerType", Reason: "invalid trigger type"}
	}

	if c.TriggerType == TriggerPeriodic && c.PushInterval <= 0 {
		return ErrInvalidConfig{Field: "PushInterval", Reason: "must be positive for periodic triggers"}
	}

	if c.MaxConcurrentPushes < 1 {
		return ErrInvalidConfig{Field: "MaxConcurrentPushes", Reason: "must be at least 1"}
	}

	if c.OnChangeDebounce < 0 {
		return ErrInvalidConfig{Field: "OnChangeDebounce", Reason: "cannot be negative"}
	}

	return nil
}

// DefaultSchedulerConfig returns a SchedulerConfig with sensible defaults.
func DefaultSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		TriggerType:         TriggerPeriodic,
		PushInterval:        5 * time.Minute,
		MaxConcurrentPushes: 10,
		FailFast:            false,
		OnChangeDebounce:    1 * time.Second,
	}
}

// PushRequest represents a request to push a manifest.
type PushRequest struct {
	// ManifestID is the ID of the manifest being pushed.
	ManifestID string

	// Payload is the serialized manifest data.
	Payload []byte

	// ContentType is the MIME type of the payload.
	ContentType string

	// TargetIDs limits the push to specific targets (empty means all).
	TargetIDs []string

	// Trigger is what triggered this push.
	Trigger TriggerType

	// Metadata contains additional request metadata.
	Metadata map[string]string
}

// Validate validates the PushRequest fields.
func (r *PushRequest) Validate() error {
	if len(r.Payload) == 0 {
		return ErrInvalidConfig{Field: "Payload", Reason: "payload cannot be empty"}
	}

	if r.ContentType == "" {
		return ErrInvalidConfig{Field: "ContentType", Reason: "content type cannot be empty"}
	}

	return nil
}

// PushBatchResult represents the results of pushing to multiple targets.
type PushBatchResult struct {
	// ManifestID is the ID of the manifest that was pushed.
	ManifestID string

	// Results contains the result for each target.
	Results []*PushResult

	// StartedAt is when the batch operation started.
	StartedAt time.Time

	// CompletedAt is when the batch operation completed.
	CompletedAt time.Time

	// Duration is the total time taken for the batch.
	Duration time.Duration

	// TotalTargets is the number of targets attempted.
	TotalTargets int

	// SuccessCount is the number of successful pushes.
	SuccessCount int

	// FailureCount is the number of failed pushes.
	FailureCount int

	// SkippedCount is the number of skipped pushes.
	SkippedCount int
}

// AllSuccess returns true if all pushes were successful.
func (r *PushBatchResult) AllSuccess() bool {
	return r.FailureCount == 0 && r.SuccessCount > 0
}

// AnySuccess returns true if at least one push was successful.
func (r *PushBatchResult) AnySuccess() bool {
	return r.SuccessCount > 0
}

// GetFailedResults returns only the failed results.
func (r *PushBatchResult) GetFailedResults() []*PushResult {
	failed := make([]*PushResult, 0, r.FailureCount)
	for _, result := range r.Results {
		if result.Status == PushStatusFailed {
			failed = append(failed, result)
		}
	}
	return failed
}

// GetSuccessResults returns only the successful results.
func (r *PushBatchResult) GetSuccessResults() []*PushResult {
	successful := make([]*PushResult, 0, r.SuccessCount)
	for _, result := range r.Results {
		if result.Status == PushStatusSuccess {
			successful = append(successful, result)
		}
	}
	return successful
}
