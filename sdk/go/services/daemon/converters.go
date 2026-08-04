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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// systemStatusFromProto converts a proto SystemStatus to a domain SystemStatus.
var systemStatusMap = map[platformv1.SystemStatus]SystemStatus{
	platformv1.SystemStatus_SYSTEM_STATUS_READY:         SystemStatusReady,
	platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING:  SystemStatusInitializing,
	platformv1.SystemStatus_SYSTEM_STATUS_DEGRADED:      SystemStatusDegraded,
	platformv1.SystemStatus_SYSTEM_STATUS_UNAVAILABLE:   SystemStatusUnavailable,
	platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN: SystemStatusShuttingDown,
}

// SystemStatusFromProto converts a proto SystemStatus to a domain SystemStatus.
func SystemStatusFromProto(s platformv1.SystemStatus) SystemStatus {
	if v, ok := systemStatusMap[s]; ok {
		return v
	}
	return SystemStatusUnspecified
}

// healthStatusMap maps proto HealthStatus to domain HealthStatus.
var healthStatusMap = map[platformv1.HealthStatus]HealthStatus{
	platformv1.HealthStatus_HEALTH_STATUS_HEALTHY:   HealthStatusHealthy,
	platformv1.HealthStatus_HEALTH_STATUS_DEGRADED:  HealthStatusDegraded,
	platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY: HealthStatusUnhealthy,
}

// HealthStatusFromProto converts a proto HealthStatus to a domain HealthStatus.
func HealthStatusFromProto(s platformv1.HealthStatus) HealthStatus {
	if v, ok := healthStatusMap[s]; ok {
		return v
	}
	return HealthStatusUnspecified
}

// serviceTypeMap maps proto ServiceType to domain ServiceType.
var serviceTypeMap = map[platformv1.ServiceType]ServiceType{
	platformv1.ServiceType_SERVICE_TYPE_TPM:         ServiceTypeTPM,
	platformv1.ServiceType_SERVICE_TYPE_SDN:         ServiceTypeSDN,
	platformv1.ServiceType_SERVICE_TYPE_COMPUTE:     ServiceTypeCompute,
	platformv1.ServiceType_SERVICE_TYPE_DNS:         ServiceTypeDNS,
	platformv1.ServiceType_SERVICE_TYPE_ACME:        ServiceTypeACME,
	platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE:  ServiceTypeWebService,
	platformv1.ServiceType_SERVICE_TYPE_ATTESTATION: ServiceTypeAttestation,
}

// ServiceTypeFromProto converts a proto ServiceType to a domain ServiceType.
func ServiceTypeFromProto(t platformv1.ServiceType) ServiceType {
	if v, ok := serviceTypeMap[t]; ok {
		return v
	}
	return ServiceTypeUnspecified
}

// serviceTypeToProtoMap maps domain ServiceType strings to proto ServiceType.
var serviceTypeToProtoMap = map[string]platformv1.ServiceType{
	"tpm":         platformv1.ServiceType_SERVICE_TYPE_TPM,
	"sdn":         platformv1.ServiceType_SERVICE_TYPE_SDN,
	"compute":     platformv1.ServiceType_SERVICE_TYPE_COMPUTE,
	"dns":         platformv1.ServiceType_SERVICE_TYPE_DNS,
	"acme":        platformv1.ServiceType_SERVICE_TYPE_ACME,
	"webservice":  platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE,
	"web":         platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE,
	"attestation": platformv1.ServiceType_SERVICE_TYPE_ATTESTATION,
}

// ServiceTypeToProto converts a service type string to a proto ServiceType.
// Returns SERVICE_TYPE_UNSPECIFIED and false if the string is not recognized.
func ServiceTypeToProto(s string) (platformv1.ServiceType, bool) {
	v, ok := serviceTypeToProtoMap[s]
	if !ok {
		return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, false
	}
	return v, true
}

// serviceStatusMap maps proto ServiceStatus to domain ServiceStatus.
var serviceStatusMap = map[platformv1.ServiceStatus]ServiceStatus{
	platformv1.ServiceStatus_SERVICE_STATUS_RUNNING:  ServiceStatusRunning,
	platformv1.ServiceStatus_SERVICE_STATUS_STOPPED:  ServiceStatusStopped,
	platformv1.ServiceStatus_SERVICE_STATUS_STARTING: ServiceStatusStarting,
	platformv1.ServiceStatus_SERVICE_STATUS_STOPPING: ServiceStatusStopping,
	platformv1.ServiceStatus_SERVICE_STATUS_ERROR:    ServiceStatusError,
}

// ServiceStatusFromProto converts a proto ServiceStatus to a domain ServiceStatus.
func ServiceStatusFromProto(s platformv1.ServiceStatus) ServiceStatus {
	if v, ok := serviceStatusMap[s]; ok {
		return v
	}
	return ServiceStatusUnspecified
}

// tpmVersionMap maps proto TPMVersion to domain TPMVersion.
var tpmVersionMap = map[platformv1.TPMVersion]TPMVersion{
	platformv1.TPMVersion_TPM_VERSION_2_0: TPMVersion20,
	platformv1.TPMVersion_TPM_VERSION_1_2: TPMVersion12,
}

// TPMVersionFromProto converts a proto TPMVersion to a domain TPMVersion.
func TPMVersionFromProto(v platformv1.TPMVersion) TPMVersion {
	if tv, ok := tpmVersionMap[v]; ok {
		return tv
	}
	return TPMVersionUnspecified
}

// VersionInfoFromProto converts a proto GetVersionResponse to a domain VersionInfo.
func VersionInfoFromProto(resp *platformv1.GetVersionResponse) *VersionInfo {
	if resp == nil {
		return nil
	}
	return &VersionInfo{
		Version:    resp.Version,
		BuildTime:  resp.BuildTime,
		GitCommit:  resp.GitCommit,
		GoVersion:  resp.GoVersion,
		Components: resp.Components,
	}
}

// StatusInfoFromProto converts a proto GetStatusResponse to a domain StatusInfo.
func StatusInfoFromProto(resp *platformv1.GetStatusResponse) *StatusInfo {
	if resp == nil {
		return nil
	}
	info := &StatusInfo{
		Status: SystemStatusFromProto(resp.Status),
	}
	if resp.Info != nil {
		info.Info = platformInfoFromProto(resp.Info)
	}
	for _, svc := range resp.Services {
		info.Services = append(info.Services, ServiceInfoFromProto(svc))
	}
	return info
}

// platformInfoFromProto converts a proto PlatformInfo to a domain PlatformInfo.
func platformInfoFromProto(p *platformv1.PlatformInfo) *PlatformInfo {
	if p == nil {
		return nil
	}
	pi := &PlatformInfo{
		Hostname:   p.Hostname,
		PlatformID: p.PlatformId,
		Version:    p.Version,
		BuildTime:  p.BuildTime,
		GitCommit:  p.GitCommit,
		FIPSMode:   p.FipsMode,
	}
	if p.SystemInfo != nil {
		pi.SystemInfo = &SystemInfo{
			OS:                p.SystemInfo.Os,
			Arch:              p.SystemInfo.Arch,
			KernelVersion:     p.SystemInfo.KernelVersion,
			NumCPUs:           p.SystemInfo.NumCpus,
			TotalMemoryMB:     p.SystemInfo.TotalMemoryMb,
			AvailableMemoryMB: p.SystemInfo.AvailableMemoryMb,
			UptimeSeconds:     p.SystemInfo.UptimeSeconds,
		}
	}
	if p.TpmInfo != nil {
		pi.TPMInfo = &TPMInfo{
			Version:         TPMVersionFromProto(p.TpmInfo.Version),
			Manufacturer:    p.TpmInfo.Manufacturer,
			FirmwareVersion: p.TpmInfo.FirmwareVersion,
			IsSimulator:     p.TpmInfo.IsSimulator,
			FIPSMode:        p.TpmInfo.FipsMode,
		}
	}
	return pi
}

// HealthInfoFromProto converts a proto GetHealthResponse to a domain HealthInfo.
func HealthInfoFromProto(resp *platformv1.GetHealthResponse) *HealthInfo {
	if resp == nil {
		return nil
	}
	hi := &HealthInfo{
		Status: HealthStatusFromProto(resp.Status),
	}
	for _, c := range resp.Components {
		hi.Components = append(hi.Components, &ComponentHealth{
			Name:    c.Name,
			Status:  HealthStatusFromProto(c.Status),
			Message: c.Message,
		})
	}
	return hi
}

// ServiceInfoFromProto converts a proto ServiceInfo to a domain ServiceInfo.
func ServiceInfoFromProto(svc *platformv1.ServiceInfo) *ServiceInfo {
	if svc == nil {
		return nil
	}
	return &ServiceInfo{
		Name:          svc.Name,
		Type:          ServiceTypeFromProto(svc.Type),
		Status:        ServiceStatusFromProto(svc.Status),
		Health:        HealthStatusFromProto(svc.Health),
		UptimeSeconds: svc.UptimeSeconds,
		Version:       svc.Version,
	}
}

// ConfigSectionsFromProto converts proto ConfigSections to domain ConfigSections.
func ConfigSectionsFromProto(sections []*platformv1.ConfigSection) []*ConfigSection {
	result := make([]*ConfigSection, 0, len(sections))
	for _, s := range sections {
		result = append(result, &ConfigSection{
			Section: s.Section,
			Values:  s.Values,
		})
	}
	return result
}
