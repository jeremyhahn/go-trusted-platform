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

// Package barrier provides a client for barrier storage service operations.
package barrier

import "time"

// Strategy represents the barrier unseal strategy.
type Strategy string

const (
	// StrategyUnspecified indicates no strategy is set.
	StrategyUnspecified Strategy = "unspecified"
	// StrategySingleKey indicates single-key unseal mode.
	StrategySingleKey Strategy = "single-key"
	// StrategyShamir indicates Shamir secret sharing unseal mode.
	StrategyShamir Strategy = "shamir"
)

// InitParams contains parameters for barrier initialization.
type InitParams struct {
	// Secret is the root secret for single-key mode.
	Secret string
	// Threshold is the minimum shares required to unseal (>= 2 for Shamir mode).
	Threshold int32
	// Shares is the total number of Shamir shares to generate.
	Shares int32
}

// InitResult contains the share-free result of barrier initialization.
// Share material is never returned over the wire; Security Officers
// claim their individual shares via the share-claim flow.
type InitResult struct {
	// Strategy is the unseal strategy used.
	Strategy Strategy `json:"strategy" yaml:"strategy"`
	// RootToken is the root token (single-key mode only).
	RootToken string `json:"root_token,omitempty" yaml:"root_token,omitempty"`
	// Threshold is the minimum number of shares required to unseal (Shamir mode).
	Threshold int32 `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// SharesTotal is the total number of Shamir shares generated.
	SharesTotal int32 `json:"shares_total,omitempty" yaml:"shares_total,omitempty"`
	// ShareCount is the number of shares sealed to enrolled Security Officers.
	ShareCount int32 `json:"share_count,omitempty" yaml:"share_count,omitempty"`
	// InitializedAt is when the barrier was initialized.
	InitializedAt *time.Time `json:"initialized_at,omitempty" yaml:"initialized_at,omitempty"`
}

// StatusResult contains the barrier status.
type StatusResult struct {
	// Initialized indicates whether the barrier has been initialized.
	Initialized bool `json:"initialized" yaml:"initialized"`
	// Sealed indicates whether the barrier is sealed.
	Sealed bool `json:"sealed" yaml:"sealed"`
	// Strategy is the unseal strategy.
	Strategy Strategy `json:"strategy" yaml:"strategy"`
	// Threshold is the Shamir threshold.
	Threshold int32 `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// SharesTotal is the total number of Shamir shares.
	SharesTotal int32 `json:"shares_total,omitempty" yaml:"shares_total,omitempty"`
	// SharesProvided is the number of shares provided so far.
	SharesProvided int32 `json:"shares_provided,omitempty" yaml:"shares_provided,omitempty"`
	// InitializedAt is when the barrier was initialized.
	InitializedAt *time.Time `json:"initialized_at,omitempty" yaml:"initialized_at,omitempty"`
}

// UnsealParams contains parameters for unsealing the barrier.
type UnsealParams struct {
	// Secret is the unseal key or Shamir share.
	Secret string
}

// UnsealResult contains the result of an unseal operation.
type UnsealResult struct {
	// Sealed indicates whether the barrier is still sealed.
	Sealed bool `json:"sealed" yaml:"sealed"`
	// SharesProvided is the number of shares provided so far (Shamir mode).
	SharesProvided int32 `json:"shares_provided,omitempty" yaml:"shares_provided,omitempty"`
	// SharesThreshold is the threshold required (Shamir mode).
	SharesThreshold int32 `json:"shares_threshold,omitempty" yaml:"shares_threshold,omitempty"`
}

// SealResult contains the result of a seal operation.
type SealResult struct {
	// Sealed indicates whether the barrier is sealed.
	Sealed bool `json:"sealed" yaml:"sealed"`
}

// RekeyParams contains parameters for rekeying the barrier.
type RekeyParams struct {
	// Threshold is the minimum shares required to unseal (>= 2 for Shamir mode).
	Threshold int32
	// Shares is the total number of Shamir shares to generate.
	Shares int32
}

// RekeyResult contains the share-free result of a rekey operation. New
// shares are sealed to enrolled Security Officers and claimed via the
// share-claim flow.
type RekeyResult struct {
	// Strategy is the new unseal strategy.
	Strategy Strategy `json:"strategy" yaml:"strategy"`
	// Threshold is the new minimum number of shares required to unseal.
	Threshold int32 `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// SharesTotal is the new total number of Shamir shares.
	SharesTotal int32 `json:"shares_total,omitempty" yaml:"shares_total,omitempty"`
	// ShareCount is the number of shares sealed to enrolled Security Officers.
	ShareCount int32 `json:"share_count,omitempty" yaml:"share_count,omitempty"`
}
