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

package cluster

import (
	"time"
)

// Config defines the configuration for cluster-aware CA operations.
type Config struct {
	// NodeID is the unique identifier for this cluster node
	NodeID string

	// TenantID is the default tenant identifier for multi-tenancy support
	TenantID string

	// CRLUpdateInterval is how often CRLs should be regenerated
	CRLUpdateInterval time.Duration

	// OrderExpirationDuration is how long ACME orders remain valid
	OrderExpirationDuration time.Duration

	// AuthorizationExpirationDuration is how long ACME authorizations remain valid
	AuthorizationExpirationDuration time.Duration

	// EnableOptimisticLocking enables version-based optimistic locking
	EnableOptimisticLocking bool

	// MaxRetries is the maximum number of retry attempts for failed operations
	MaxRetries int

	// RetryBackoff is the initial backoff duration for retry attempts
	RetryBackoff time.Duration

	// ConsistencyLevel defines the consistency requirements for operations
	// (linearizable, sequential, eventual)
	ConsistencyLevel ConsistencyLevel
}

// ConsistencyLevel defines the consistency requirements for cluster operations.
type ConsistencyLevel string

const (
	// ConsistencyLinearizable ensures all operations are linearizable (strongest)
	ConsistencyLinearizable ConsistencyLevel = "linearizable"

	// ConsistencySequential ensures sequential consistency
	ConsistencySequential ConsistencyLevel = "sequential"

	// ConsistencyEventual allows eventual consistency (weakest, highest performance)
	ConsistencyEventual ConsistencyLevel = "eventual"
)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(nodeID string) *Config {
	return &Config{
		NodeID:                          nodeID,
		TenantID:                        "default",
		CRLUpdateInterval:               24 * time.Hour,
		OrderExpirationDuration:         7 * 24 * time.Hour, // 7 days
		AuthorizationExpirationDuration: 7 * 24 * time.Hour, // 7 days
		EnableOptimisticLocking:         true,
		MaxRetries:                      3,
		RetryBackoff:                    100 * time.Millisecond,
		ConsistencyLevel:                ConsistencyLinearizable,
	}
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.NodeID == "" {
		return ErrInvalidInput{Field: "NodeID", Reason: "must not be empty"}
	}
	if c.TenantID == "" {
		return ErrInvalidInput{Field: "TenantID", Reason: "must not be empty"}
	}
	if c.CRLUpdateInterval <= 0 {
		return ErrInvalidInput{Field: "CRLUpdateInterval", Reason: "must be positive"}
	}
	if c.OrderExpirationDuration <= 0 {
		return ErrInvalidInput{Field: "OrderExpirationDuration", Reason: "must be positive"}
	}
	if c.AuthorizationExpirationDuration <= 0 {
		return ErrInvalidInput{Field: "AuthorizationExpirationDuration", Reason: "must be positive"}
	}
	if c.MaxRetries < 0 {
		return ErrInvalidInput{Field: "MaxRetries", Reason: "must not be negative"}
	}
	if c.RetryBackoff <= 0 {
		return ErrInvalidInput{Field: "RetryBackoff", Reason: "must be positive"}
	}

	switch c.ConsistencyLevel {
	case ConsistencyLinearizable, ConsistencySequential, ConsistencyEventual:
		// Valid
	default:
		return ErrInvalidInput{Field: "ConsistencyLevel", Reason: "invalid consistency level"}
	}

	return nil
}

// WithNodeID sets the node ID.
func (c *Config) WithNodeID(nodeID string) *Config {
	c.NodeID = nodeID
	return c
}

// WithTenantID sets the tenant ID.
func (c *Config) WithTenantID(tenantID string) *Config {
	c.TenantID = tenantID
	return c
}

// WithCRLUpdateInterval sets the CRL update interval.
func (c *Config) WithCRLUpdateInterval(interval time.Duration) *Config {
	c.CRLUpdateInterval = interval
	return c
}

// WithOrderExpiration sets the ACME order expiration duration.
func (c *Config) WithOrderExpiration(duration time.Duration) *Config {
	c.OrderExpirationDuration = duration
	return c
}

// WithAuthorizationExpiration sets the ACME authorization expiration duration.
func (c *Config) WithAuthorizationExpiration(duration time.Duration) *Config {
	c.AuthorizationExpirationDuration = duration
	return c
}

// WithOptimisticLocking enables or disables optimistic locking.
func (c *Config) WithOptimisticLocking(enabled bool) *Config {
	c.EnableOptimisticLocking = enabled
	return c
}

// WithRetryPolicy sets the retry policy parameters.
func (c *Config) WithRetryPolicy(maxRetries int, backoff time.Duration) *Config {
	c.MaxRetries = maxRetries
	c.RetryBackoff = backoff
	return c
}

// WithConsistencyLevel sets the consistency level.
func (c *Config) WithConsistencyLevel(level ConsistencyLevel) *Config {
	c.ConsistencyLevel = level
	return c
}
