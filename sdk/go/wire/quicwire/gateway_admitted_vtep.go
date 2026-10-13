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

package quicwire

// GatewayAdmittedVTEPInfo is a remote VTEP the gateway admitted to the overlay,
// with the device and attestation verdict that admitted it.
type GatewayAdmittedVTEPInfo struct {
	VTEP           string `codec:"vtep"`
	DeviceID       uint64 `codec:"device_id,omitempty"`
	HostID         string `codec:"host_id,omitempty"`
	Serial         string `codec:"serial,omitempty"`
	Hostname       string `codec:"hostname,omitempty"`
	AllocationID   string `codec:"allocation_id,omitempty"`
	BaselineSource string `codec:"baseline_source,omitempty"`
	ProfileID      uint64 `codec:"profile_id,omitempty"`
	VerdictAt      int64  `codec:"verdict_at,omitempty"`
}

// GatewayAdmittedVTEPRequest asks for one admitted VTEP by address.
type GatewayAdmittedVTEPRequest struct {
	GatewayID string `codec:"gateway_id,omitempty"`
	VTEP      string `codec:"vtep"`
}

// GatewayAdmittedVTEPResponse carries one admitted VTEP.
type GatewayAdmittedVTEPResponse struct {
	VTEP      *GatewayAdmittedVTEPInfo `codec:"vtep"`
	Timestamp int64                    `codec:"timestamp"`
}

// GatewayListAdmittedVTEPsRequest asks for every VTEP a gateway admitted.
type GatewayListAdmittedVTEPsRequest struct {
	GatewayID string `codec:"gateway_id,omitempty"`
}

// GatewayListAdmittedVTEPsResponse carries every VTEP a gateway admitted.
type GatewayListAdmittedVTEPsResponse struct {
	VTEPs     []*GatewayAdmittedVTEPInfo `codec:"vteps"`
	Count     int32                      `codec:"count"`
	Timestamp int64                      `codec:"timestamp"`
}
