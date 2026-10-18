// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// This file implements the PXECommands interface through the platform SDK.

//go:build integration

package pxe

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	// Register the sdk/go transports the SDK adapters select by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
)

// The proto enum names are the suite's state names, upper-cased and prefixed.
const (
	provisioningStatePrefix = "PROVISIONING_STATE_"
	eventTypePrefix         = "PROVISIONING_EVENT_TYPE_"
)

// SDKAdapter drives PXECommands through the platform SDK over one selected
// transport, exercising the exact adapter tables (QUIC sub-opcode map, MCP
// tool map) the production clients use.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	client   platform.Client
	pxe      platformv1.PXEServiceClient
}

// Name returns the protocol adapter identifier.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, a.options())
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.pxe = client.PXE()
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// callFailed wraps err with the transport and the PXEService method it failed.
func (a *SDKAdapter) callFailed(method string, err error) error {
	return ErrRequestFailed{Protocol: a.name, Method: method, Err: err}
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device (PXEService/RegisterDevice).
func (a *SDKAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	resp, err := a.pxe.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{
		MacAddress: opts.MACAddress,
		PortId:     opts.PortID,
	})
	if err != nil {
		return nil, a.callFailed("RegisterDevice", err)
	}
	d := resp.GetDevice()
	return &RegisterDeviceResult{
		ID:          d.GetId(),
		MACAddress:  d.GetMacAddress(),
		PortID:      d.GetPortId(),
		State:       stateName(d.GetState()),
		StateReason: d.GetStateReason(),
		CurrentVLAN: uint16(d.GetCurrentVlan()),
		CreatedAt:   timeOf(d.GetCreatedAt()),
	}, nil
}

// GetDevice retrieves a device by ID (PXEService/GetDevice).
func (a *SDKAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	resp, err := a.pxe.GetDevice(ctx, &platformv1.GetPXEDeviceRequest{DeviceId: deviceID})
	if err != nil {
		return nil, a.callFailed("GetDevice", err)
	}
	return deviceResult(resp.GetDevice()), nil
}

// GetDeviceByMAC retrieves a device by MAC address (PXEService/GetDeviceByMAC).
func (a *SDKAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	resp, err := a.pxe.GetDeviceByMAC(ctx, &platformv1.GetPXEDeviceByMACRequest{MacAddress: mac})
	if err != nil {
		return nil, a.callFailed("GetDeviceByMAC", err)
	}
	return deviceResult(resp.GetDevice()), nil
}

// ListDevices lists devices matching opts (PXEService/ListDevices).
func (a *SDKAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	filter := &platformv1.PXEDeviceFilter{
		MacAddress: opts.MACAddress,
		Vlan:       uint32(opts.VLAN),
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}
	if opts.State != "" {
		state, err := stateValue("ListDevices", opts.State)
		if err != nil {
			return nil, err
		}
		filter.State = state
	}
	resp, err := a.pxe.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{Filter: filter})
	if err != nil {
		return nil, a.callFailed("ListDevices", err)
	}
	result := &ListDevicesResult{TotalCount: resp.GetTotalCount()}
	for _, d := range resp.GetDevices() {
		result.Devices = append(result.Devices, DeviceSummary{
			ID:          d.GetId(),
			MACAddress:  d.GetMacAddress(),
			PortID:      d.GetPortId(),
			State:       stateName(d.GetState()),
			CurrentVLAN: uint16(d.GetCurrentVlan()),
			CreatedAt:   timeOf(d.GetCreatedAt()),
			UpdatedAt:   timeOf(d.GetUpdatedAt()),
		})
	}
	return result, nil
}

// RemoveDevice removes a device (PXEService/RemoveDevice).
func (a *SDKAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	if _, err := a.pxe.RemoveDevice(ctx, &platformv1.RemovePXEDeviceRequest{DeviceId: deviceID}); err != nil {
		return nil, a.callFailed("RemoveDevice", err)
	}
	return &RemoveDeviceResult{ID: deviceID, Removed: true}, nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState moves a device to a new state (PXEService/UpdateState).
// The response carries only the device after the move, so the state it left
// is read with GetDevice first.
func (a *SDKAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	state, err := stateValue("UpdateDeviceState", opts.State)
	if err != nil {
		return nil, err
	}
	before, err := a.GetDevice(ctx, opts.DeviceID)
	if err != nil {
		return nil, err
	}
	resp, err := a.pxe.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: opts.DeviceID,
		State:    state,
		Reason:   opts.Reason,
	})
	if err != nil {
		return nil, a.callFailed("UpdateState", err)
	}
	d := resp.GetDevice()
	return &UpdateStateResult{
		ID:        d.GetId(),
		FromState: before.State,
		ToState:   stateName(d.GetState()),
		Reason:    d.GetStateReason(),
		UpdatedAt: timeOf(d.GetUpdatedAt()),
	}, nil
}

// SetDeviceEnrolled records a device's enrollment certificate
// (PXEService/SetDeviceEnrolled).
func (a *SDKAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	resp, err := a.pxe.SetDeviceEnrolled(ctx, &platformv1.SetPXEDeviceEnrolledRequest{
		DeviceId:          deviceID,
		CertificateSerial: certSerial,
	})
	if err != nil {
		return nil, a.callFailed("SetDeviceEnrolled", err)
	}
	d := resp.GetDevice()
	return &SetEnrolledResult{
		ID:                d.GetId(),
		State:             stateName(d.GetState()),
		CertificateSerial: d.GetCertificateSerial(),
		UpdatedAt:         timeOf(d.GetUpdatedAt()),
	}, nil
}

// AuthorizeDevice moves a device onto its target VLAN (PXEService/Authorize).
func (a *SDKAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	resp, err := a.pxe.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{
		DeviceId:   deviceID,
		TargetVlan: uint32(targetVLAN),
	})
	if err != nil {
		return nil, a.callFailed("Authorize", err)
	}
	d := resp.GetDevice()
	return &AuthorizeResult{
		ID:         d.GetId(),
		State:      stateName(d.GetState()),
		TargetVLAN: uint16(d.GetTargetVlan()),
		UpdatedAt:  timeOf(d.GetUpdatedAt()),
	}, nil
}

// QuarantineDevice quarantines a device (PXEService/Quarantine).
func (a *SDKAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	resp, err := a.pxe.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{
		DeviceId: deviceID,
		Reason:   reason,
	})
	if err != nil {
		return nil, a.callFailed("Quarantine", err)
	}
	d := resp.GetDevice()
	return &QuarantineResult{
		ID:          d.GetId(),
		State:       stateName(d.GetState()),
		Reason:      d.GetStateReason(),
		CurrentVLAN: uint16(d.GetCurrentVlan()),
		UpdatedAt:   timeOf(d.GetUpdatedAt()),
	}, nil
}

// RetryDevice restarts provisioning of a device (PXEService/Retry).
func (a *SDKAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	resp, err := a.pxe.Retry(ctx, &platformv1.RetryPXEDeviceRequest{DeviceId: deviceID})
	if err != nil {
		return nil, a.callFailed("Retry", err)
	}
	d := resp.GetDevice()
	return &RetryResult{
		ID:         d.GetId(),
		State:      stateName(d.GetState()),
		RetryCount: int(d.GetRetryCount()),
		UpdatedAt:  timeOf(d.GetUpdatedAt()),
	}, nil
}

// =============================================================================
// Event and Service Status Commands
// =============================================================================

// GetEvents lists a device's provisioning events (PXEService/GetEvents).
func (a *SDKAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	resp, err := a.pxe.GetEvents(ctx, &platformv1.GetPXEEventsRequest{DeviceId: deviceID})
	if err != nil {
		return nil, a.callFailed("GetEvents", err)
	}
	result := &GetEventsResult{DeviceID: deviceID}
	for _, e := range resp.GetEvents() {
		result.Events = append(result.Events, ProvisioningEventInfo{
			ID:        e.GetId(),
			DeviceID:  e.GetDeviceId(),
			EventType: strings.ToLower(strings.TrimPrefix(e.GetEventType().String(), eventTypePrefix)),
			FromState: stateName(e.GetFromState()),
			ToState:   stateName(e.GetToState()),
			Details:   e.GetDetails(),
			Error:     e.GetError(),
			Timestamp: timeOf(e.GetTimestamp()),
		})
	}
	return result, nil
}

// GetStatus reports the PXE service status (PXEService/GetStatus).
func (a *SDKAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	resp, err := a.pxe.GetStatus(ctx, &platformv1.GetPXEStatusRequest{})
	if err != nil {
		return nil, a.callFailed("GetStatus", err)
	}
	s := resp.GetStatus()
	return &GetStatusResult{
		Running:          s.GetRunning(),
		DeviceCount:      int(s.GetDeviceCount()),
		StartTime:        timeOf(s.GetStartTime()),
		IPXEServerAddr:   s.GetIpxeServerAddr(),
		QuarantineVLAN:   uint16(s.GetQuarantineVlan()),
		ProvisioningVLAN: uint16(s.GetProvisioningVlan()),
	}, nil
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// deviceResult converts a PXEDeviceInfo into the suite's device result.
func deviceResult(d *platformv1.PXEDeviceInfo) *GetDeviceResult {
	return &GetDeviceResult{
		ID:                d.GetId(),
		MACAddress:        d.GetMacAddress(),
		PortID:            d.GetPortId(),
		State:             stateName(d.GetState()),
		StateReason:       d.GetStateReason(),
		CertificateSerial: d.GetCertificateSerial(),
		CurrentVLAN:       uint16(d.GetCurrentVlan()),
		TargetVLAN:        uint16(d.GetTargetVlan()),
		RetryCount:        int(d.GetRetryCount()),
		CreatedAt:         timeOf(d.GetCreatedAt()),
		UpdatedAt:         timeOf(d.GetUpdatedAt()),
		StateChangedAt:    timeOf(d.GetStateChangedAt()),
	}
}

// stateName gives the suite's name for a provisioning state ("install_complete"
// for PROVISIONING_STATE_INSTALL_COMPLETE).
func stateName(state platformv1.ProvisioningState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), provisioningStatePrefix))
}

// stateValue gives the provisioning state the suite's name stands for.
func stateValue(operation, name string) (platformv1.ProvisioningState, error) {
	value, ok := platformv1.ProvisioningState_value[provisioningStatePrefix+strings.ToUpper(name)]
	if !ok {
		return platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED,
			ErrInvalidOperation{Operation: operation, Reason: "unknown provisioning state " + name}
	}
	return platformv1.ProvisioningState(value), nil
}

// timeOf converts a proto timestamp, leaving an absent one as the zero time.
func timeOf(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// Ensure SDKAdapter implements PXECommands interface.
var _ PXECommands = (*SDKAdapter)(nil)
