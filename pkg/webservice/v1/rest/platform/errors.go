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

package platform

import "fmt"

// ErrServiceNotFound is returned when a requested service does not exist
type ErrServiceNotFound struct {
	ServiceName string
}

func (e ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceName)
}

// ErrServiceAlreadyRunning is returned when attempting to start an already running service
type ErrServiceAlreadyRunning struct {
	ServiceName string
}

func (e ErrServiceAlreadyRunning) Error() string {
	return fmt.Sprintf("service already running: %s", e.ServiceName)
}

// ErrServiceNotRunning is returned when attempting operations on a stopped service
type ErrServiceNotRunning struct {
	ServiceName string
}

func (e ErrServiceNotRunning) Error() string {
	return fmt.Sprintf("service is not running: %s", e.ServiceName)
}

// ErrServiceStartFailed is returned when a service fails to start
type ErrServiceStartFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStartFailed) Error() string {
	return fmt.Sprintf("service %s failed to start: %s", e.ServiceName, e.Reason)
}

// ErrServiceStopFailed is returned when a service fails to stop
type ErrServiceStopFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStopFailed) Error() string {
	return fmt.Sprintf("service %s failed to stop: %s", e.ServiceName, e.Reason)
}

// ErrHealthRegistryNotConfigured is returned when health check operations
// are attempted but the health registry is not configured
type ErrHealthRegistryNotConfigured struct{}

func (e ErrHealthRegistryNotConfigured) Error() string {
	return "health registry not configured"
}

// ErrServiceRegistryNotConfigured is returned when service operations
// are attempted but the service registry is not configured
type ErrServiceRegistryNotConfigured struct{}

func (e ErrServiceRegistryNotConfigured) Error() string {
	return "service registry not configured"
}

// ErrDaemonConfigNotConfigured is returned when protocol status is requested
// but the daemon config is not configured
type ErrDaemonConfigNotConfigured struct{}

func (e ErrDaemonConfigNotConfigured) Error() string {
	return "daemon config not configured"
}
