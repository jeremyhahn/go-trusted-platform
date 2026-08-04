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

package daemon

import (
	"context"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// GetVersionDomain returns version information using domain types.
func (c *Client) GetVersionDomain(ctx context.Context) (*VersionInfo, error) {
	resp, err := c.grpc.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return nil, &ErrGetVersionFailed{Cause: err}
	}
	return VersionInfoFromProto(resp), nil
}

// GetStatusDomain returns the current platform status using domain types.
func (c *Client) GetStatusDomain(ctx context.Context) (*StatusInfo, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return StatusInfoFromProto(resp), nil
}

// GetHealthDomain returns the health status using domain types.
func (c *Client) GetHealthDomain(ctx context.Context, detailed bool) (*HealthInfo, error) {
	resp, err := c.grpc.GetHealth(ctx, &platformv1.GetHealthRequest{Detailed: detailed})
	if err != nil {
		return nil, &ErrGetHealthFailed{Cause: err}
	}
	return HealthInfoFromProto(resp), nil
}

// GetConfigDomain returns configuration sections using domain types.
func (c *Client) GetConfigDomain(ctx context.Context, section string) ([]*ConfigSection, error) {
	resp, err := c.grpc.GetConfig(ctx, &platformv1.GetConfigRequest{Section: section})
	if err != nil {
		return nil, &ErrGetConfigFailed{Cause: err}
	}
	return ConfigSectionsFromProto(resp.Sections), nil
}

// UpdateConfigDomain updates a configuration section using domain types.
// Returns true on success, or an error with the failure message.
func (c *Client) UpdateConfigDomain(ctx context.Context, section string, values map[string]string, persist bool) (bool, error) {
	resp, err := c.grpc.UpdateConfig(ctx, &platformv1.UpdateConfigRequest{
		Section: &platformv1.ConfigSection{
			Section: section,
			Values:  values,
		},
		Persist: persist,
	})
	if err != nil {
		return false, &ErrUpdateConfigFailed{Section: section, Cause: err}
	}
	if resp.Status != nil && !resp.Status.Success {
		msg := "unknown error"
		if resp.Status.Error != nil {
			msg = resp.Status.Error.Message
		}
		return false, &ErrUpdateConfigFailed{Section: section, Cause: &ErrStatusMessage{Message: msg}}
	}
	return true, nil
}

// ReloadConfigDomain reloads configuration and returns reloaded sections.
func (c *Client) ReloadConfigDomain(ctx context.Context) ([]string, error) {
	resp, err := c.grpc.ReloadConfig(ctx, &platformv1.ReloadConfigRequest{})
	if err != nil {
		return nil, &ErrReloadConfigFailed{Cause: err}
	}
	if resp.Status != nil && !resp.Status.Success {
		msg := "unknown error"
		if resp.Status.Error != nil {
			msg = resp.Status.Error.Message
		}
		return nil, &ErrReloadConfigFailed{Cause: &ErrStatusMessage{Message: msg}}
	}
	return resp.ReloadedSections, nil
}

// ListServicesDomain returns a list of services using domain types.
func (c *Client) ListServicesDomain(ctx context.Context) ([]*ServiceInfo, error) {
	resp, err := c.grpc.ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return nil, &ErrListServicesFailed{Cause: err}
	}
	services := make([]*ServiceInfo, 0, len(resp.Services))
	for _, svc := range resp.Services {
		services = append(services, ServiceInfoFromProto(svc))
	}
	return services, nil
}

// StartServiceDomain starts a service by type name string.
// Returns the started service info on success.
func (c *Client) StartServiceDomain(ctx context.Context, serviceType string) (*ServiceInfo, error) {
	svcType, ok := ServiceTypeToProto(strings.ToLower(serviceType))
	if !ok {
		return nil, &ErrStartServiceFailed{Service: serviceType, Cause: &ErrUnknownServiceType{Type: serviceType}}
	}
	resp, err := c.grpc.StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, &ErrStartServiceFailed{Service: serviceType, Cause: err}
	}
	if resp.Status != nil && !resp.Status.Success {
		msg := "unknown error"
		if resp.Status.Error != nil {
			msg = resp.Status.Error.Message
		}
		return nil, &ErrStartServiceFailed{Service: serviceType, Cause: &ErrStatusMessage{Message: msg}}
	}
	return ServiceInfoFromProto(resp.Service), nil
}

// StopServiceDomain stops a service by type name string.
func (c *Client) StopServiceDomain(ctx context.Context, serviceType string, force bool, timeoutSeconds uint32) error {
	svcType, ok := ServiceTypeToProto(strings.ToLower(serviceType))
	if !ok {
		return &ErrStopServiceFailed{Service: serviceType, Cause: &ErrUnknownServiceType{Type: serviceType}}
	}
	resp, err := c.grpc.StopService(ctx, &platformv1.StopServiceRequest{
		Service:        svcType,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return &ErrStopServiceFailed{Service: serviceType, Cause: err}
	}
	if resp.Status != nil && !resp.Status.Success {
		msg := "unknown error"
		if resp.Status.Error != nil {
			msg = resp.Status.Error.Message
		}
		return &ErrStopServiceFailed{Service: serviceType, Cause: &ErrStatusMessage{Message: msg}}
	}
	return nil
}

// RestartServiceDomain restarts a service by type name string.
// Returns the restarted service info on success.
func (c *Client) RestartServiceDomain(ctx context.Context, serviceType string, timeoutSeconds uint32) (*ServiceInfo, error) {
	svcType, ok := ServiceTypeToProto(strings.ToLower(serviceType))
	if !ok {
		return nil, &ErrRestartServiceFailed{Service: serviceType, Cause: &ErrUnknownServiceType{Type: serviceType}}
	}
	resp, err := c.grpc.RestartService(ctx, &platformv1.RestartServiceRequest{
		Service:        svcType,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return nil, &ErrRestartServiceFailed{Service: serviceType, Cause: err}
	}
	if resp.Status != nil && !resp.Status.Success {
		msg := "unknown error"
		if resp.Status.Error != nil {
			msg = resp.Status.Error.Message
		}
		return nil, &ErrRestartServiceFailed{Service: serviceType, Cause: &ErrStatusMessage{Message: msg}}
	}
	return ServiceInfoFromProto(resp.Service), nil
}

// GetServiceStatusDomain returns the status of a service by type name string.
func (c *Client) GetServiceStatusDomain(ctx context.Context, serviceType string) (*ServiceInfo, error) {
	svcType, ok := ServiceTypeToProto(strings.ToLower(serviceType))
	if !ok {
		return nil, &ErrGetServiceStatusFailed{Service: serviceType, Cause: &ErrUnknownServiceType{Type: serviceType}}
	}
	resp, err := c.grpc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: svcType})
	if err != nil {
		return nil, &ErrGetServiceStatusFailed{Service: serviceType, Cause: err}
	}
	return ServiceInfoFromProto(resp.Service), nil
}
