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

package container

import "fmt"

// ErrContainerNotFound is returned when a container cannot be found
type ErrContainerNotFound struct {
	ID string
}

func (e ErrContainerNotFound) Error() string {
	return fmt.Sprintf("container not found: %s", e.ID)
}

// ErrContainerOperationFailed is returned when a container operation fails
type ErrContainerOperationFailed struct {
	Operation string
	ID        string
	Err       error
}

func (e ErrContainerOperationFailed) Error() string {
	return fmt.Sprintf("container %s failed for %s: %v", e.Operation, e.ID, e.Err)
}

// Unwrap returns the underlying error
func (e ErrContainerOperationFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidContainerConfig is returned when container configuration is invalid
type ErrInvalidContainerConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidContainerConfig) Error() string {
	return fmt.Sprintf("invalid container config: %s - %s", e.Field, e.Reason)
}

// ErrInvalidPortMapping is returned when port mapping is invalid
type ErrInvalidPortMapping struct {
	Mapping string
}

func (e ErrInvalidPortMapping) Error() string {
	return fmt.Sprintf("invalid port mapping: %s (expected format: hostPort:containerPort or hostPort:containerPort/protocol)", e.Mapping)
}

// ErrInvalidMountSpec is returned when mount specification is invalid
type ErrInvalidMountSpec struct {
	Spec string
}

func (e ErrInvalidMountSpec) Error() string {
	return fmt.Sprintf("invalid mount specification: %s (expected format: hostPath:containerPath[:ro])", e.Spec)
}

// ErrInvalidEnvVar is returned when environment variable specification is invalid
type ErrInvalidEnvVar struct {
	Spec string
}

func (e ErrInvalidEnvVar) Error() string {
	return fmt.Sprintf("invalid environment variable: %s (expected format: KEY=value)", e.Spec)
}

// ErrInvalidLabel is returned when label specification is invalid
type ErrInvalidLabel struct {
	Spec string
}

func (e ErrInvalidLabel) Error() string {
	return fmt.Sprintf("invalid label: %s (expected format: key=value)", e.Spec)
}

// ErrContainerClientNotInitialized is returned when the compute client is not initialized
type ErrContainerClientNotInitialized struct{}

func (e ErrContainerClientNotInitialized) Error() string {
	return "container client not initialized"
}

// ErrContainerAlreadyRunning is returned when attempting to start an already running container
type ErrContainerAlreadyRunning struct {
	ID string
}

func (e ErrContainerAlreadyRunning) Error() string {
	return fmt.Sprintf("container already running: %s", e.ID)
}

// ErrContainerNotRunning is returned when attempting to stop a non-running container
type ErrContainerNotRunning struct {
	ID string
}

func (e ErrContainerNotRunning) Error() string {
	return fmt.Sprintf("container not running: %s", e.ID)
}

// ErrInvalidMemorySpec is returned when memory specification is invalid
type ErrInvalidMemorySpec struct {
	Spec string
}

func (e ErrInvalidMemorySpec) Error() string {
	return fmt.Sprintf("invalid memory specification: %s (expected format: 512m, 1g, etc.)", e.Spec)
}

// ErrInvalidCPUSpec is returned when CPU specification is invalid
type ErrInvalidCPUSpec struct {
	Spec string
}

func (e ErrInvalidCPUSpec) Error() string {
	return fmt.Sprintf("invalid CPU specification: %s (expected format: 0.5, 1, 2, etc.)", e.Spec)
}

// ErrAttestationFailed is returned when container attestation fails
type ErrAttestationFailed struct {
	ID  string
	Err error
}

func (e ErrAttestationFailed) Error() string {
	return fmt.Sprintf("attestation failed for container %s: %v", e.ID, e.Err)
}

// Unwrap returns the underlying error
func (e ErrAttestationFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidFilter is returned when an invalid filter is specified
type ErrInvalidFilter struct {
	Filter string
}

func (e ErrInvalidFilter) Error() string {
	return fmt.Sprintf("invalid filter: %s (expected format: key=value)", e.Filter)
}
