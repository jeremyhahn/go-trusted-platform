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

// This file implements the BMCCommands interface using REST HTTP calls.

//go:build integration

package bmc_integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// REST Adapter Constants
// =============================================================================

const (
	// DefaultRESTTimeout is the default timeout for REST requests.
	DefaultRESTTimeout = 30 * time.Second

	// bmcRESTBasePath is the base path for BMC REST API endpoints.
	bmcRESTBasePath = "/api/v1/bmc"
)

// restEnvelope is the server-side WebServiceResponse wrapper that surrounds
// every payload returned by the daemon's REST API.
type restEnvelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements BMCCommands using REST HTTP calls.
type RESTAdapter struct {
	endpoint   string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for BMC integration testing.
func NewRESTAdapter() *RESTAdapter {
	endpoint := getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint)

	return &RESTAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(DefaultRESTTimeout),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST connection and verifies connectivity.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	// Verify connectivity with a power status check
	_, err := r.PowerStatus(ctx, DefaultTestProfileID)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.endpoint, Err: err}
	}
	return nil
}

// Teardown performs cleanup.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

func (r *RESTAdapter) bmcURL(profileID uint64, segments ...string) string {
	url := fmt.Sprintf("%s%s/%d", r.endpoint, bmcRESTBasePath, profileID)
	for _, seg := range segments {
		url += "/" + seg
	}
	return url
}

func (r *RESTAdapter) doGet(ctx context.Context, url string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{URL: url, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if resp.StatusCode >= 400 {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if result == nil || len(body) == 0 {
		return nil
	}

	var env restEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if env.Error != "" {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: env.Error}
	}

	if len(env.Payload) > 0 {
		if err := json.Unmarshal(env.Payload, result); err != nil {
			return ErrRESTRequestFailed{Err: err}
		}
	}

	return nil
}

func (r *RESTAdapter) doPost(ctx context.Context, url string, payload interface{}, result interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{URL: url, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if resp.StatusCode >= 400 {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if result == nil || len(body) == 0 {
		return nil
	}

	var env restEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if env.Error != "" {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: env.Error}
	}

	if len(env.Payload) > 0 {
		if err := json.Unmarshal(env.Payload, result); err != nil {
			return ErrRESTRequestFailed{Err: err}
		}
	}

	return nil
}

func (r *RESTAdapter) doDelete(ctx context.Context, url string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{URL: url, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if resp.StatusCode >= 400 {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if result == nil || len(body) == 0 {
		return nil
	}

	var env restEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if env.Error != "" {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: env.Error}
	}

	if len(env.Payload) > 0 {
		if err := json.Unmarshal(env.Payload, result); err != nil {
			return ErrRESTRequestFailed{Err: err}
		}
	}

	return nil
}

// =============================================================================
// Power Operations
// =============================================================================

// PowerOn powers on a BMC-managed system via REST.
func (r *RESTAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	var resp restPowerActionResponse
	payload := map[string]string{"action": "on"}
	if err := r.doPost(ctx, r.bmcURL(profileID, "power"), payload, &resp); err != nil {
		return nil, err
	}
	return &bmcsvc.PowerResponse{CurrentState: bmcsvc.PowerStateOn}, nil
}

// PowerOff powers off a BMC-managed system via REST.
func (r *RESTAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	var resp restPowerActionResponse
	payload := map[string]string{"action": "off"}
	if err := r.doPost(ctx, r.bmcURL(profileID, "power"), payload, &resp); err != nil {
		return nil, err
	}
	return &bmcsvc.PowerResponse{CurrentState: bmcsvc.PowerStateOff}, nil
}

// PowerStatus queries the current power state via REST.
func (r *RESTAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	var resp restPowerStatusResponse
	if err := r.doGet(ctx, r.bmcURL(profileID, "power"), &resp); err != nil {
		return bmcsvc.PowerStateUnspecified, err
	}
	state, ok := bmcsvc.ParsePowerState(resp.PowerState)
	if !ok {
		return bmcsvc.PowerStateUnknown, nil
	}
	return state, nil
}

// =============================================================================
// Boot Device Operations
// =============================================================================

// SetBootDevice sets the boot device via REST.
func (r *RESTAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	payload := restBootDeviceRequest{
		Device:     string(device),
		Persistent: persistent,
	}
	var resp restBootDeviceResponse
	return r.doPost(ctx, r.bmcURL(profileID, "boot-device"), payload, &resp)
}

// GetBootDevice queries the current boot device via REST.
func (r *RESTAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	var resp restBootDeviceResponse
	if err := r.doGet(ctx, r.bmcURL(profileID, "boot-device"), &resp); err != nil {
		return bmcsvc.BootDeviceUnspecified, err
	}
	device, ok := bmcsvc.ParseBootDevice(resp.Device)
	if !ok {
		return bmcsvc.BootDeviceUnspecified, nil
	}
	return device, nil
}

// =============================================================================
// Virtual Media Operations
// =============================================================================

// MountISO mounts an ISO via REST.
func (r *RESTAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	payload := restMountMediaRequest{ISOURL: isoURL}
	var resp restMediaActionResponse
	return r.doPost(ctx, r.bmcURL(profileID, "virtual-media"), payload, &resp)
}

// UnmountISO unmounts virtual media via REST.
func (r *RESTAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	var resp restMediaActionResponse
	return r.doDelete(ctx, r.bmcURL(profileID, "virtual-media"), &resp)
}

// VirtualMediaStatus queries virtual media status via REST.
func (r *RESTAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	var resp restMediaStatusResponse
	if err := r.doGet(ctx, r.bmcURL(profileID, "virtual-media"), &resp); err != nil {
		return nil, err
	}
	return &bmcsvc.VirtualMediaInfo{
		Mounted:  resp.Mounted,
		ImageURL: resp.ISOURL,
	}, nil
}

// =============================================================================
// Sensor Operations
// =============================================================================

// GetSensors queries sensor readings via REST.
func (r *RESTAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	var resp []restSensorReading
	if err := r.doGet(ctx, r.bmcURL(profileID, "sensors"), &resp); err != nil {
		return nil, err
	}
	sensors := make([]bmcsvc.SensorReading, len(resp))
	for i, s := range resp {
		sensors[i] = bmcsvc.SensorReading{
			Name:   s.Name,
			Value:  s.Value,
			Units:  s.Units,
			Status: bmcsvc.SensorStatus(s.Status),
		}
	}
	return sensors, nil
}

// =============================================================================
// System Info Operations
// =============================================================================

// GetSystemInfo queries system information via REST.
func (r *RESTAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	var resp restSystemInfoResponse
	if err := r.doGet(ctx, r.bmcURL(profileID, "system-info"), &resp); err != nil {
		return nil, err
	}
	powerState, _ := bmcsvc.ParsePowerState(resp.PowerState)
	return &bmcsvc.SystemInfo{
		Manufacturer:    resp.Manufacturer,
		Product:         resp.Model,
		SerialNumber:    resp.SerialNumber,
		FirmwareVersion: resp.BMCVersion,
		BIOSVersion:     resp.BIOSVersion,
		PowerState:      powerState,
	}, nil
}

// =============================================================================
// Certificate Operations
// =============================================================================

// GetWebCertificate queries the BMC web certificate via REST.
func (r *RESTAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	var resp bmcsvc.CertificateInfo
	if err := r.doGet(ctx, r.bmcURL(profileID, "cert"), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// =============================================================================
// User Management Operations
// =============================================================================

// ListUsers lists BMC users via REST.
func (r *RESTAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	var resp []restUserInfo
	if err := r.doGet(ctx, r.bmcURL(profileID, "users"), &resp); err != nil {
		return nil, err
	}
	users := make([]bmcsvc.User, len(resp))
	for i, u := range resp {
		priv, _ := bmcsvc.ParsePrivilege(ipmiPrivilegeName(u.Privilege))
		users[i] = bmcsvc.User{
			Slot:      u.Slot,
			Username:  u.Username,
			Enabled:   u.Enabled,
			Privilege: priv,
			Channel:   u.Channel,
		}
	}
	return users, nil
}

// =============================================================================
// Enrollment Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony via the REST API.
// POST /api/v1/bmc/{profileID}/enroll
func (r *RESTAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	var body restEnrollRequest
	if opts != nil {
		body.ReplaceCertificate = opts.ReplaceCertificate
		body.RotatePassword = opts.RotatePassword
		body.DNSRegister = opts.DNSRegister
		body.DANEPublish = opts.DANEPublish
	}

	var resp restEnrollResponse
	if err := r.doPost(ctx, r.bmcURL(profileID, "enroll"), body, &resp); err != nil {
		return nil, err
	}
	return restEnrollResponseToDomain(&resp), nil
}

// restEnrollResponseToDomain converts the REST wire response to the local
// domain EnrollResult type.
func restEnrollResponseToDomain(r *restEnrollResponse) *EnrollResult {
	if r == nil {
		return &EnrollResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &EnrollResult{
		DeviceID:      r.DeviceID,
		Endpoint:      r.Endpoint,
		Hostname:      r.Hostname,
		DNSName:       r.DNSName,
		PinSPKISHA256: r.PinSPKISHA256,
		FactoryCertMeta: EnrollFactoryCertMeta{
			Subject:      r.FactoryCertMeta.Subject,
			Issuer:       r.FactoryCertMeta.Issuer,
			SerialNumber: r.FactoryCertMeta.SerialNumber,
			NotBefore:    r.FactoryCertMeta.NotBefore,
			NotAfter:     r.FactoryCertMeta.NotAfter,
			SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
			SHA256:       r.FactoryCertMeta.SHA256,
			CapturedAt:   r.FactoryCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}

// =============================================================================
// Factory Certificate Restore Operations
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony via the REST API.
// POST /api/v1/bmc/{profileID}/cert/restore
func (r *RESTAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	var resp restRestoreResponse
	if err := r.doPost(ctx, r.bmcURL(profileID, "cert", "restore"), nil, &resp); err != nil {
		return nil, err
	}
	return restRestoreResponseToDomain(&resp), nil
}

// restRestoreResponseToDomain converts the REST wire response to the local
// domain RestoreResult type.
func restRestoreResponseToDomain(r *restRestoreResponse) *RestoreResult {
	if r == nil {
		return &RestoreResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &RestoreResult{
		DeviceID: r.DeviceID,
		Endpoint: r.Endpoint,
		Hostname: r.Hostname,
		NewCertMeta: RestoreFactoryCertMeta{
			Subject:      r.NewCertMeta.Subject,
			Issuer:       r.NewCertMeta.Issuer,
			SerialNumber: r.NewCertMeta.SerialNumber,
			NotBefore:    r.NewCertMeta.NotBefore,
			NotAfter:     r.NewCertMeta.NotAfter,
			SPKISHA256:   r.NewCertMeta.SPKISHA256,
			SHA256:       r.NewCertMeta.SHA256,
			CapturedAt:   r.NewCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}

// =============================================================================
// REST Response Types
// =============================================================================

type restPowerStatusResponse struct {
	ProfileID  string `json:"profile_id"`
	PowerState string `json:"power_state"`
}

type restPowerActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

type restBootDeviceRequest struct {
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

type restBootDeviceResponse struct {
	ProfileID  string `json:"profile_id"`
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

type restMountMediaRequest struct {
	ISOURL string `json:"iso_url"`
}

type restMediaStatusResponse struct {
	ProfileID string `json:"profile_id"`
	Mounted   bool   `json:"mounted"`
	ISOURL    string `json:"iso_url,omitempty"`
}

type restMediaActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

type restSensorReading struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Units  string  `json:"units"`
	Status string  `json:"status"`
}

type restSensorsResponse struct {
	ProfileID string              `json:"profile_id"`
	Sensors   []restSensorReading `json:"sensors"`
}

type restSystemInfoResponse struct {
	ProfileID    string `json:"profile_id"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	BIOSVersion  string `json:"bios_version"`
	BMCVersion   string `json:"bmc_version"`
	PowerState   string `json:"power_state"`
}

type restUserInfo struct {
	Slot     uint32 `json:"slot"`
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
	// Privilege is the IPMI privilege enum value as serialized by the daemon
	// (uint8: 4=administrator, 3=operator, 2=user, 1=callback, else no-access).
	Privilege uint8  `json:"privilege"`
	Channel   uint32 `json:"channel"`
}

// ipmiPrivilegeName maps the IPMI privilege enum value to the canonical
// lowercase name accepted by bmcsvc.ParsePrivilege.
func ipmiPrivilegeName(p uint8) string {
	switch p {
	case 4:
		return "administrator"
	case 3:
		return "operator"
	case 2:
		return "user"
	case 1:
		return "callback"
	default:
		return "no-access"
	}
}

type restUsersResponse struct {
	ProfileID string         `json:"profile_id"`
	Users     []restUserInfo `json:"users"`
}

// restEnrollRequest is the JSON body sent to POST /api/v1/bmc/{profileID}/enroll.
type restEnrollRequest struct {
	ReplaceCertificate *bool `json:"replace_certificate,omitempty"`
	RotatePassword     *bool `json:"rotate_password,omitempty"`
	DNSRegister        *bool `json:"dns_register,omitempty"`
	DANEPublish        *bool `json:"dane_publish,omitempty"`
}

// restEnrollStep mirrors pkg/webservice/v1/bmc.EnrollStepResponse.
type restEnrollStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// restFactoryCertMeta mirrors pkg/webservice/v1/bmc.FactoryCertMetaResponse.
type restFactoryCertMeta struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// restEnrollResponse mirrors pkg/webservice/v1/bmc.EnrollResponse.
// DeviceID uses the `json:",string"` tag to match the server's uint64-as-string
// serialisation that preserves precision across JavaScript JSON parsers.
type restEnrollResponse struct {
	DeviceID        uint64              `json:"device_id,string"`
	Endpoint        string              `json:"endpoint"`
	Hostname        string              `json:"hostname"`
	DNSName         string              `json:"dns_name,omitempty"`
	PinSPKISHA256   string              `json:"pin_spki_sha256"`
	FactoryCertMeta restFactoryCertMeta `json:"factory_cert_meta"`
	Steps           []restEnrollStep    `json:"steps"`
}

// restRestoreResponse mirrors pkg/webservice/v1/bmc.RestoreResponse.
// DeviceID uses `json:",string"` for uint64 precision preservation.
type restRestoreResponse struct {
	DeviceID    uint64              `json:"device_id,string"`
	Endpoint    string              `json:"endpoint"`
	Hostname    string              `json:"hostname"`
	NewCertMeta restFactoryCertMeta `json:"new_cert_meta"`
	Steps       []restEnrollStep    `json:"steps"`
}

// Ensure RESTAdapter implements BMCCommands interface.
var _ BMCCommands = (*RESTAdapter)(nil)
