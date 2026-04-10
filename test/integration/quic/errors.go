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

// Package quic provides integration tests for the QUIC protocol handlers.
package quic

import "fmt"

// ErrConnectionFailed is returned when the QUIC client fails to connect.
type ErrConnectionFailed struct {
	Address string
	Cause   error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("failed to connect to QUIC server at %s: %v", e.Address, e.Cause)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrRequestFailed is returned when a QUIC request fails.
type ErrRequestFailed struct {
	Opcode byte
	Cause  error
}

func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request failed for opcode 0x%02X: %v", e.Opcode, e.Cause)
}

func (e ErrRequestFailed) Unwrap() error {
	return e.Cause
}

// ErrUnexpectedStatus is returned when an unexpected status is received.
type ErrUnexpectedStatus struct {
	Expected byte
	Actual   byte
	Message  string
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("unexpected status: expected 0x%02X, got 0x%02X: %s", e.Expected, e.Actual, e.Message)
}

// ErrDecodeFailed is returned when decoding a response payload fails.
type ErrDecodeFailed struct {
	Cause error
}

func (e ErrDecodeFailed) Error() string {
	return fmt.Sprintf("failed to decode response payload: %v", e.Cause)
}

func (e ErrDecodeFailed) Unwrap() error {
	return e.Cause
}

// ErrEncodeFailed is returned when encoding a request payload fails.
type ErrEncodeFailed struct {
	Cause error
}

func (e ErrEncodeFailed) Error() string {
	return fmt.Sprintf("failed to encode request payload: %v", e.Cause)
}

func (e ErrEncodeFailed) Unwrap() error {
	return e.Cause
}

// ErrTestSetupFailed is returned when test setup fails.
type ErrTestSetupFailed struct {
	Component string
	Cause     error
}

func (e ErrTestSetupFailed) Error() string {
	return fmt.Sprintf("test setup failed for %s: %v", e.Component, e.Cause)
}

func (e ErrTestSetupFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceUnavailable is returned when a required service is not available.
type ErrServiceUnavailable struct {
	Service string
}

func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("service unavailable: %s", e.Service)
}
