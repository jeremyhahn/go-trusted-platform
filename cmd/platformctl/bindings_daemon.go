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

package main

import (
	"log/slog"
	"strings"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DaemonBinding exposes daemon service methods to the Wails frontend.
type DaemonBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewDaemonBinding creates a new DaemonBinding.
func NewDaemonBinding(logger *slog.Logger, conn *ConnectionBinding) *DaemonBinding {
	return &DaemonBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *DaemonBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GetVersion returns the daemon version information.
func (b *DaemonBinding) GetVersion() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Daemon().GetVersion(b.conn.ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"version":   resp.GetVersion(),
		"buildTime": resp.GetBuildTime(),
		"gitCommit": resp.GetGitCommit(),
		"goVersion": resp.GetGoVersion(),
	}, nil
}

// GetStatus returns the daemon status.
func (b *DaemonBinding) GetStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Daemon().GetStatus(b.conn.ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"status": resp.GetStatus().String(),
	}

	if info := resp.GetInfo(); info != nil {
		result["hostname"] = info.GetHostname()
		result["platformId"] = info.GetPlatformId()
		result["version"] = info.GetVersion()
	}

	var services []map[string]interface{}
	for _, svc := range resp.GetServices() {
		services = append(services, map[string]interface{}{
			"name":   svc.GetName(),
			"status": svc.GetStatus().String(),
			"health": svc.GetHealth().String(),
		})
	}
	result["services"] = services

	return result, nil
}

// GetHealth returns the daemon health.
func (b *DaemonBinding) GetHealth(detailed bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Daemon().GetHealth(b.conn.ctx, &platformv1.GetHealthRequest{
		Detailed: detailed,
	})
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"status": resp.GetStatus().String(),
	}

	if detailed {
		var components []map[string]interface{}
		for _, comp := range resp.GetComponents() {
			components = append(components, map[string]interface{}{
				"name":   comp.GetName(),
				"status": comp.GetStatus().String(),
			})
		}
		result["components"] = components
	}

	return result, nil
}

// ListServices returns a list of platform services.
func (b *DaemonBinding) ListServices() ([]map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Daemon().ListServices(b.conn.ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return nil, err
	}

	var services []map[string]interface{}
	for _, svc := range resp.GetServices() {
		services = append(services, map[string]interface{}{
			"name":   svc.GetName(),
			"type":   svc.GetType().String(),
			"status": svc.GetStatus().String(),
			"health": svc.GetHealth().String(),
		})
	}

	return services, nil
}

// StartService starts a platform service by type name.
func (b *DaemonBinding) StartService(serviceType string) error {
	cl, err := b.getClient()
	if err != nil {
		return err
	}

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	_, err = cl.Daemon().StartService(b.conn.ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	return err
}

// StopService stops a platform service by type name.
func (b *DaemonBinding) StopService(serviceType string) error {
	cl, err := b.getClient()
	if err != nil {
		return err
	}

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	_, err = cl.Daemon().StopService(b.conn.ctx, &platformv1.StopServiceRequest{
		Service: svcType,
	})
	return err
}

// RestartService restarts a platform service by type name.
func (b *DaemonBinding) RestartService(serviceType string) error {
	cl, err := b.getClient()
	if err != nil {
		return err
	}

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return err
	}

	_, err = cl.Daemon().RestartService(b.conn.ctx, &platformv1.RestartServiceRequest{
		Service: svcType,
	})
	return err
}

// GetServiceStatus returns the status of a specific service.
func (b *DaemonBinding) GetServiceStatus(serviceType string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	svcType, err := parseServiceType(serviceType)
	if err != nil {
		return nil, err
	}

	resp, err := cl.Daemon().GetServiceStatus(b.conn.ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, err
	}

	svc := resp.GetService()
	if svc == nil {
		return map[string]interface{}{
			"type":   serviceType,
			"status": "unknown",
		}, nil
	}

	return map[string]interface{}{
		"name":   svc.GetName(),
		"type":   svc.GetType().String(),
		"status": svc.GetStatus().String(),
		"health": svc.GetHealth().String(),
	}, nil
}

// parseServiceType converts a service type string to the protobuf enum.
// It accepts both short names (e.g., "tpm") and full enum names
// (e.g., "SERVICE_TYPE_TPM").
func parseServiceType(input string) (platformv1.ServiceType, error) {
	upper := strings.ToUpper(input)

	// Try full enum name first.
	if val, ok := platformv1.ServiceType_value[upper]; ok {
		return platformv1.ServiceType(val), nil
	}

	// Try with SERVICE_TYPE_ prefix.
	prefixed := "SERVICE_TYPE_" + upper
	if val, ok := platformv1.ServiceType_value[prefixed]; ok {
		return platformv1.ServiceType(val), nil
	}

	return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, &InvalidServiceTypeError{Input: input}
}
