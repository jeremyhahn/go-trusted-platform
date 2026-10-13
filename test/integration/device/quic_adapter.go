//go:build integration

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

package device

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Errors
// =============================================================================

// QUICAdapterError represents an error from the QUIC adapter.
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// ErrQUICStatus reports a non-OK status byte from the daemon, carrying the
// byte itself so a test can assert WHICH refusal it got rather than only
// that something failed.
type ErrQUICStatus struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICStatus) Error() string {
	return fmt.Sprintf("QUIC %s refused with status 0x%02X: %s", e.Operation, e.Status, e.Message)
}

// =============================================================================
// QUIC Adapter
// =============================================================================

const (
	quicDialTimeout = 15 * time.Second
	quicIdleTimeout = 60 * time.Second
	quicKeepAlive   = 15 * time.Second
)

// deviceGetRequest mirrors the daemon's union wire request for
// OpDeviceGet (0x32) and OpDeviceGetState (0x3D), which is a daemon-native
// struct rather than a platform.v1 message: `Id` selects GetDevice and an
// empty `Id` with a `Serial` selects FindDeviceBySerial. The field names
// must match `deviceGetWireRequest` in pkg/api/daemon/quic_device_handlers.go
// exactly, because the codec keys on Go field names.
type deviceGetRequest struct {
	Id     uint64
	Serial string
}

// QUICAdapter implements DeviceCommands over the platform's binary QUIC
// protocol.
//
// It calls pkg/api/quic's own WriteRequest / ReadResponse / EncodePayload /
// DecodePayload rather than reimplementing the framing, so the adapter and
// the daemon cannot drift apart: they are the same code. Requests are
// [opcode 1B | token_len 2B | token | payload_len 4B | payload] with the
// payload encoded by the platform codec over platform.v1 messages;
// responses are [status 1B | payload_len 4B | payload].
//
// Before #480 this adapter wrote a JSON {method, path, body} envelope on the
// stream. The daemon's QUIC server reads the binary framing above, so the
// envelope reached no handler on any method, and the suite's skip guard
// turned each failure into a skip. It also offered ALPN "device-quic" while
// the server offers only "platform-quic", so the TLS handshake could not
// complete either.
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config
	conn      *quicgo.Conn
	mu        sync.RWMutex
}

// NewQUICAdapter creates a binary-protocol QUIC adapter for device tests.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint: helpers.GetQUICEndpoint(),
		// The daemon's QUIC listener offers exactly one ALPN protocol,
		// "platform-quic" (pkg/api/quic/config.go). Offering any other
		// name fails the handshake with no_application_protocol before a
		// single stream is opened.
		tlsConfig: helpers.QUICTLSConfig(),
	}
}

// quicALPN is the ALPN protocol the daemon's QUIC listener negotiates, taken
// from the server package rather than retyped. The previous adapter offered
// "device-quic", which no listener has ever advertised.
const quicALPN = quicwire.ALPNProtocol

// Name returns the adapter name.
func (a *QUICAdapter) Name() string { return "QUIC" }

// Setup establishes the QUIC connection.
func (a *QUICAdapter) Setup(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, quicDialTimeout)
	defer cancel()

	conn, err := quicgo.DialAddr(dialCtx, a.endpoint, a.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  quicIdleTimeout,
		KeepAlivePeriod: quicKeepAlive,
	})
	if err != nil {
		return &QUICAdapterError{Operation: "Setup", Message: "dial " + a.endpoint + ": " + err.Error()}
	}

	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	return nil
}

// Teardown closes the QUIC connection.
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return nil
	}
	err := a.conn.CloseWithError(0, "teardown")
	a.conn = nil
	return err
}

// =============================================================================
// Binary protocol round trip
// =============================================================================

// call encodes body, performs one opcode round trip, and decodes the reply
// into out. A nil body sends an empty payload; a nil out discards the reply.
func (a *QUICAdapter) call(ctx context.Context, op string, opcode byte, body, out interface{}) error {
	var payload []byte
	if body != nil {
		encoded, err := quicwire.EncodePayload(body)
		if err != nil {
			return &QUICAdapterError{Operation: op, Message: "encode: " + err.Error()}
		}
		payload = encoded
	}
	return a.roundTrip(ctx, op, opcode, payload, out)
}

// callCategory performs a category round trip, where payload[0] is the
// sub-opcode and the remainder is the encoded body. Profile assignment
// travels this way under OpProvisioningCategory because the single-byte
// opcode space is fully allocated.
func (a *QUICAdapter) callCategory(ctx context.Context, op string, categoryOpcode, subOpcode byte, body, out interface{}) error {
	var encoded []byte
	if body != nil {
		b, err := quicwire.EncodePayload(body)
		if err != nil {
			return &QUICAdapterError{Operation: op, Message: "encode: " + err.Error()}
		}
		encoded = b
	}
	payload := make([]byte, 1+len(encoded))
	payload[0] = subOpcode
	copy(payload[1:], encoded)
	return a.roundTrip(ctx, op, categoryOpcode, payload, out)
}

func (a *QUICAdapter) roundTrip(ctx context.Context, op string, opcode byte, payload []byte, out interface{}) error {
	a.mu.RLock()
	conn := a.conn
	a.mu.RUnlock()
	if conn == nil {
		return &QUICAdapterError{Operation: op, Message: "adapter is not connected; call Setup first"}
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return &QUICAdapterError{Operation: op, Message: "open stream: " + err.Error()}
	}
	defer stream.Close()

	// token_len is zero: the daemon authenticates these connections by the
	// mTLS client certificate, not a bearer token.
	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: opcode, Payload: payload}); err != nil {
		return &QUICAdapterError{Operation: op, Message: "write request: " + err.Error()}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return &QUICAdapterError{Operation: op, Message: "read response: " + err.Error()}
	}

	if resp.Status != quicwire.StatusOK {
		return ErrQUICStatus{Operation: op, Status: resp.Status, Message: string(resp.Payload)}
	}

	if out == nil || len(resp.Payload) == 0 {
		return nil
	}
	if err := quicwire.DecodePayload(resp.Payload, out); err != nil {
		return &QUICAdapterError{Operation: op, Message: "decode response: " + err.Error()}
	}
	return nil
}

// parseID converts a suite id string into the uint64 the wire carries.
func parseID(op, kind, raw string) (uint64, error) {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, &QUICAdapterError{Operation: op, Message: "invalid " + kind + " ID " + strconv.Quote(raw)}
	}
	return id, nil
}

// pageOf derives the 1-based page number the pagination request carries.
func pageOf(limit, offset int) uint32 {
	if limit > 0 && offset > 0 {
		return uint32(offset/limit) + 1
	}
	return 1
}

// =============================================================================
// Device CRUD
// =============================================================================

// RegisterDevice creates a device via OpDeviceRegister (0x30).
func (a *QUICAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	req := &pb.CreateDeviceRequest{
		Device: &pb.Device{
			Serial:     opts.Serial,
			Model:      opts.Model,
			EkCert:     opts.EKCert,
			AttestPub:  opts.AttestPub,
			AttestCert: opts.AttestCert,
			SigningPub: opts.SigningPub,
			HashAlgoId: opts.HashAlgoId,
		},
	}
	var resp pb.CreateDeviceResponse
	if err := a.call(ctx, "RegisterDevice", quicwire.OpDeviceRegister, req, &resp); err != nil {
		return nil, err
	}
	return &RegisterDeviceResult{Device: protoToDevice(resp.GetDevice())}, nil
}

// GetDevice reads a device via OpDeviceGet (0x32) keyed by id.
func (a *QUICAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	id, err := parseID("GetDevice", "device", opts.DeviceID)
	if err != nil {
		return nil, err
	}
	var resp pb.GetDeviceResponse
	if err := a.call(ctx, "GetDevice", quicwire.OpDeviceGet, &deviceGetRequest{Id: id}, &resp); err != nil {
		return nil, err
	}
	return &GetDeviceResult{Device: protoToDevice(resp.GetDevice())}, nil
}

// UpdateDevice updates a device via OpDeviceUpdate (0x34).
func (a *QUICAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	id, err := parseID("UpdateDevice", "device", opts.DeviceID)
	if err != nil {
		return nil, err
	}
	req := &pb.UpdateDeviceRequest{
		Device: &pb.Device{
			Id:         id,
			Model:      opts.Model,
			EkCert:     opts.EKCert,
			AttestPub:  opts.AttestPub,
			AttestCert: opts.AttestCert,
			SigningPub: opts.SigningPub,
			HashAlgoId: opts.HashAlgoId,
		},
	}
	var resp pb.UpdateDeviceResponse
	if err := a.call(ctx, "UpdateDevice", quicwire.OpDeviceUpdate, req, &resp); err != nil {
		return nil, err
	}
	return &UpdateDeviceResult{Device: protoToDevice(resp.GetDevice())}, nil
}

// DeleteDevice removes a device via OpDeviceUnregister (0x31).
func (a *QUICAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	id, err := parseID("DeleteDevice", "device", opts.DeviceID)
	if err != nil {
		return nil, err
	}
	var resp pb.DeleteDeviceResponse
	if err := a.call(ctx, "DeleteDevice", quicwire.OpDeviceUnregister, &pb.DeleteDeviceRequest{Id: id}, &resp); err != nil {
		return nil, err
	}
	return &DeleteDeviceResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// ListDevices pages devices via OpDeviceList (0x33). The reply's pagination
// carries the total, which is how the same opcode serves CountDevices.
func (a *QUICAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	req := &pb.ListDevicesRequest{
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     pageOf(opts.Limit, opts.Offset),
		},
	}
	var resp pb.ListDevicesResponse
	if err := a.call(ctx, "ListDevices", quicwire.OpDeviceList, req, &resp); err != nil {
		return nil, err
	}
	devices := make([]*entities.Device, 0, len(resp.GetDevices()))
	for _, d := range resp.GetDevices() {
		devices = append(devices, protoToDevice(d))
	}
	total := 0
	if resp.GetPagination() != nil {
		total = int(resp.GetPagination().GetTotalItems())
	}
	return &ListDevicesResult{Devices: devices, Total: total}, nil
}

// =============================================================================
// Device Lookups
// =============================================================================

// FindBySerial reads a device via OpDeviceGet (0x32) keyed by serial. The
// opcode is a union: an empty Id selects the serial lookup, and both replies
// carry the device under the same field.
func (a *QUICAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	var resp pb.FindDeviceBySerialResponse
	if err := a.call(ctx, "FindBySerial", quicwire.OpDeviceGet, &deviceGetRequest{Serial: opts.Serial}, &resp); err != nil {
		return nil, err
	}
	return &FindBySerialResult{Device: protoToDevice(resp.GetDevice())}, nil
}

// =============================================================================
// Profile CRUD
// =============================================================================

// CreateProfile creates a profile via OpDeviceCreateProfile (0x38).
func (a *QUICAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	req := &pb.CreateProfileRequest{
		Profile: &pb.DeviceProfile{
			Name:  opts.Name,
			Model: opts.Model,
			Role:  grpcapi.EntityRoleToProto(opts.Role),
			MatchRules: &pb.ProfileMatchRules{
				MacPrefix:    opts.MACPrefix,
				SerialPrefix: opts.SerialPrefix,
			},
		},
	}
	if opts.MatchRules != nil {
		req.Profile.MatchRules = entityMatchRulesToProto(opts.MatchRules)
	}
	var resp pb.CreateProfileResponse
	if err := a.call(ctx, "CreateProfile", quicwire.OpDeviceCreateProfile, req, &resp); err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: protoToProfile(resp.GetProfile())}, nil
}

// GetProfile reads a profile via OpDeviceGetProfile (0x35).
func (a *QUICAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	id, err := parseID("GetProfile", "profile", opts.ProfileID)
	if err != nil {
		return nil, err
	}
	var resp pb.GetProfileResponse
	if err := a.call(ctx, "GetProfile", quicwire.OpDeviceGetProfile, &pb.GetProfileRequest{Id: id}, &resp); err != nil {
		return nil, err
	}
	return &GetProfileResult{Profile: protoToProfile(resp.GetProfile())}, nil
}

// UpdateProfile replaces a profile via OpDeviceSetProfile (0x36).
func (a *QUICAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	id, err := parseID("UpdateProfile", "profile", opts.ProfileID)
	if err != nil {
		return nil, err
	}
	req := &pb.UpdateProfileRequest{
		Profile: &pb.DeviceProfile{
			Id:    id,
			Name:  opts.Name,
			Model: opts.Model,
			Role:  grpcapi.EntityRoleToProto(opts.Role),
		},
	}
	if opts.MatchRules != nil {
		req.Profile.MatchRules = entityMatchRulesToProto(opts.MatchRules)
	}
	var resp pb.UpdateProfileResponse
	if err := a.call(ctx, "UpdateProfile", quicwire.OpDeviceSetProfile, req, &resp); err != nil {
		return nil, err
	}
	return &UpdateProfileResult{Profile: protoToProfile(resp.GetProfile())}, nil
}

// DeleteProfile removes a profile via OpDeviceDeleteProfile (0x39).
func (a *QUICAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	id, err := parseID("DeleteProfile", "profile", opts.ProfileID)
	if err != nil {
		return nil, err
	}
	var resp pb.DeleteProfileResponse
	if err := a.call(ctx, "DeleteProfile", quicwire.OpDeviceDeleteProfile, &pb.DeleteProfileRequest{Id: id}, &resp); err != nil {
		return nil, err
	}
	return &DeleteProfileResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// ListProfiles pages profiles via OpDeviceListProfiles (0x37).
func (a *QUICAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	req := &pb.ListProfilesRequest{
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     pageOf(opts.Limit, opts.Offset),
		},
	}
	var resp pb.ListProfilesResponse
	if err := a.call(ctx, "ListProfiles", quicwire.OpDeviceListProfiles, req, &resp); err != nil {
		return nil, err
	}
	profiles := make([]*entities.DeviceProfile, 0, len(resp.GetProfiles()))
	for _, p := range resp.GetProfiles() {
		profiles = append(profiles, protoToProfile(p))
	}
	total := 0
	if resp.GetPagination() != nil {
		total = int(resp.GetPagination().GetTotalItems())
	}
	return &ListProfilesResult{Profiles: profiles, Total: total}, nil
}

// =============================================================================
// Attestation
// =============================================================================

// RecordAttestCert records the device's attestation certificate. It travels
// as a sub-opcode under OpProvisioningCategory (0xCF) for the same reason
// AssignProfileToDevice does - the single-byte opcode space is fully
// allocated; the daemon routes payload[0] == DeviceSubRecordAttestCert to
// the shared gRPC service, so QUIC answers exactly what gRPC and Unix do.
func (a *QUICAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	req := &pb.RecordAttestationCertificateRequest{
		DeviceId:       opts.DeviceID,
		Reissue:        opts.Reissue,
		ClearOnRefusal: opts.ClearOnRefusal,
	}
	var resp pb.RecordAttestationCertificateResponse
	if err := a.callCategory(ctx, "RecordAttestCert",
		quicwire.OpProvisioningCategory, quicwire.DeviceSubRecordAttestCert, req, &resp); err != nil {
		return nil, err
	}
	return &RecordAttestCertResult{
		DeviceID:          strconv.FormatUint(resp.GetDeviceId(), 10),
		Serial:            resp.GetSerial(),
		Model:             resp.GetModel(),
		Changed:           resp.GetChanged(),
		Source:            resp.GetSource(),
		SourceDetail:      resp.GetSourceDetail(),
		Reissued:          resp.GetReissued(),
		Subject:           resp.GetSubject(),
		CertificateSerial: resp.GetCertificateSerial(),
		AttestCert:        resp.GetAttestCert(),
		Cleared:           resp.GetCleared(),
		Refusal:           resp.GetRefusal(),
	}, nil
}

// AttestDevice submits quote evidence via OpDeviceAttest (0x3A). The daemon
// decodes the platform.v1 request and delegates to the shared DeviceService
// verifier, so QUIC returns the same verdict as every other transport - which
// is the point of #520: one verifier, reached identically from each.
//
// The verdict is reported as it came back. A device that does not attest is a
// successful call carrying verified=false, and this adapter does not launder
// that into a Go error: the suite has to be able to see a refusal and assert
// WHICH check refused it.
//
// Before #480 this method could not reach the daemon at all and returned
// ErrAttestationTransportUnavailable. That gap is closed, so the forged- and
// empty-evidence assertions in multiprotocol_test.go now actually execute on
// this transport rather than logging an absent surface.
func (a *QUICAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	req := &pb.AttestDeviceRequest{
		DeviceId: opts.DeviceID,
		Evidence: opts.Evidence,
	}
	var resp pb.AttestDeviceResponse
	if err := a.call(ctx, "AttestDevice", quicwire.OpDeviceAttest, req, &resp); err != nil {
		return nil, err
	}
	return attestResultFromProto(opts.DeviceID, &resp), nil
}

// =============================================================================
// Profile assignment
// =============================================================================

// AssignProfileToDevice binds a profile to a device identity. It travels as
// a sub-opcode under OpProvisioningCategory (0xCF) because the single-byte
// opcode space is fully allocated; the daemon routes payload[0] ==
// DeviceProfileSubAssign to the shared gRPC service.
func (a *QUICAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	id, err := parseID("AssignProfileToDevice", "profile", opts.ProfileID)
	if err != nil {
		return nil, err
	}
	req := &pb.AssignProfileToDeviceRequest{
		ProfileId: id,
		EkSerial:  opts.EKSerial,
	}
	var resp pb.AssignProfileToDeviceResponse
	if err := a.callCategory(ctx, "AssignProfileToDevice",
		quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign, req, &resp); err != nil {
		return nil, err
	}
	return &AssignProfileToDeviceResult{Profile: protoToProfile(resp.GetProfile())}, nil
}

// DisableDevice sends DeviceSubDisable under OpProvisioningCategory; the
// single-byte opcode space is fully allocated.
func (a *QUICAdapter) DisableDevice(ctx context.Context, opts DisableDeviceOptions) (*DeviceLifecycleResult, error) {
	req := &pb.DisableDeviceRequest{DeviceId: opts.DeviceID, Reason: opts.Reason}
	var resp pb.DeviceLifecycleResponse
	if err := a.callCategory(ctx, "DisableDevice",
		quicwire.OpProvisioningCategory, quicwire.DeviceSubDisable, req, &resp); err != nil {
		return nil, err
	}
	return lifecycleResultFromProto(&resp), nil
}

// EnableDevice sends DeviceSubEnable under OpProvisioningCategory.
func (a *QUICAdapter) EnableDevice(ctx context.Context, opts EnableDeviceOptions) (*DeviceLifecycleResult, error) {
	req := &pb.EnableDeviceRequest{DeviceId: opts.DeviceID}
	var resp pb.DeviceLifecycleResponse
	if err := a.callCategory(ctx, "EnableDevice",
		quicwire.OpProvisioningCategory, quicwire.DeviceSubEnable, req, &resp); err != nil {
		return nil, err
	}
	return lifecycleResultFromProto(&resp), nil
}

// =============================================================================
// Operations with no QUIC opcode
//
// Each returns surface.ErrNoSurface naming the gap. docs/device/api.md §2-4
// records these as MISSING on QUIC; the template rows are a deliberate
// design decision rather than an untracked hole. The error is returned
// rather than faked so the absence stays visible in the suite.
// =============================================================================

func (a *QUICAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "FindProfileByMACAddress", Reason: "docs/device/api.md §3 records QUIC as MISSING for profile lookup by MAC"}
}

func (a *QUICAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "FindProfileBySerial", Reason: "docs/device/api.md §3 records QUIC as MISSING for profile lookup by serial"}
}

func (a *QUICAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "FindMatchingProfile", Reason: "docs/device/api.md §3 records QUIC as MISSING for profile matching"}
}

func (a *QUICAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "FindConfigForDevice", Reason: "docs/device/api.md §3 records QUIC as MISSING for config lookup"}
}

// CreateTemplate stores a template through OpProvisioningCategory +
// DeviceSubTemplateCreate, served by the shared gRPC service.
func (a *QUICAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	var resp pb.DeviceTemplateCreateResponse
	if err := a.callCategory(ctx, "CreateTemplate",
		quicwire.OpProvisioningCategory, quicwire.DeviceSubTemplateCreate, templateCreateRequest(opts), &resp); err != nil {
		return nil, err
	}
	return &CreateTemplateResult{Template: protoToTemplate(resp.GetTemplate())}, nil
}

func (a *QUICAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetTemplate", Reason: templateNoSurfaceReason}
}

func (a *QUICAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "UpdateTemplate", Reason: templateNoSurfaceReason}
}

func (a *QUICAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "DeleteTemplate", Reason: templateNoSurfaceReason}
}

func (a *QUICAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "ListTemplates", Reason: templateNoSurfaceReason}
}

// CreateProfileFromTemplate builds a profile through OpProvisioningCategory
// + DeviceSubProfileFromTemplate, served by the shared gRPC service.
func (a *QUICAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	id, err := parseID("CreateProfileFromTemplate", "template", opts.TemplateID)
	if err != nil {
		return nil, err
	}
	req := &pb.CreateProfileFromTemplateRequest{
		TemplateId: id,
		Overrides: &pb.DeviceProfile{
			Name:       opts.Name,
			EkSerial:   opts.EKSerial,
			MacAddress: opts.MACAddress,
		},
	}
	var resp pb.CreateProfileResponse
	if err := a.callCategory(ctx, "CreateProfileFromTemplate",
		quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate, req, &resp); err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: protoToProfile(resp.GetProfile())}, nil
}

// templateNoSurfaceReason cites the recorded decision rather than treating
// the absence as an oversight: docs/device/api.md §4 states that template
// read, update, delete and list are REST-only; only CreateTemplate and
// CreateProfileFromTemplate are on the wire.
const templateNoSurfaceReason = "docs/device/api.md §4 records template read/update/delete/list as REST-only"
