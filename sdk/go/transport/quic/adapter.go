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

// Package quic provides the QUIC transport adapter for the platform SDK.
// It wraps the pkg/api/quic client and provides a gRPC-compatible interface
// for service clients, using UDP transport with TLS 1.3.
package quic

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/pollstream"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolQUIC, Connect)
}

// Adapter implements the transport.Adapter interface for QUIC over UDP.
type Adapter struct {
	client    *quicwire.Client
	connected atomic.Bool
	closed    atomic.Bool
	address   string
	timeout   time.Duration
}

// Connect establishes a QUIC connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.QUICAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	timeout := opts.GetTimeout()

	// Build QUIC client configuration
	clientConfig := &quicwire.ClientConfig{
		ServerAddr:     opts.QUICAddr,
		TLSConfig:      opts.ClientTLSConfig(),
		Timeout:        timeout,
		MaxIdleTimeout: timeout * 2,
		NextProtos:     []string{"platform-quic"},
	}

	// The QUIC server authenticates every framed request by its token, and
	// the transport is always TLS 1.3, so the bearer token rides each frame.
	var clientOpts []quicwire.ClientOption
	if opts.BearerToken != "" {
		clientOpts = append(clientOpts, quicwire.WithToken(opts.BearerToken))
	}

	// Create QUIC client; NewClient dials and completes the handshake.
	start := time.Now()
	client, err := quicwire.NewClient(clientConfig, clientOpts...)
	if err != nil {
		if transport.IsTimeout(err) {
			err = platform.ErrTimeout{Operation: "QUIC handshake", Elapsed: time.Since(start), Err: err}
		}
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolQUIC,
			Target:   opts.QUICAddr,
			Err:      err,
		}
	}

	a := &Adapter{
		client:  client,
		address: opts.QUICAddr,
		timeout: timeout,
	}
	a.connected.Store(true)

	return a, nil
}

// Connection returns a gRPC-compatible client connection interface.
// This wraps the QUIC adapter to provide a unified interface for service clients.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return &quicClientConn{adapter: a, sender: &realQUICSender{client: a.client}}
}

// Close closes the QUIC client connection.
func (a *Adapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	a.connected.Store(false)

	if a.client != nil {
		err := a.client.Close()
		if err != nil {
			return platform.ErrCloseFailed{
				Protocol: platform.ProtocolQUIC,
				Err:      err,
			}
		}
	}

	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	if a.client == nil {
		return false
	}
	return a.connected.Load() && !a.closed.Load() && a.client.IsConnected()
}

// Target returns the QUIC server address.
func (a *Adapter) Target() string {
	return a.address
}

// Client returns the underlying QUIC client for direct access.
func (a *Adapter) Client() *quicwire.Client {
	return a.client
}

// SetToken sets the authentication token for QUIC requests.
func (a *Adapter) SetToken(token string) {
	if a.client != nil {
		a.client.SetToken(token)
	}
}

// quicSender abstracts the QUIC client transport so tests can inject a
// recorder and assert on the exact bytes that hit the wire. The two
// methods mirror the two send modes used by Invoke: RPC-style for
// regular opcodes (encode args / decode reply) and raw-byte mode for
// category opcodes where the SDK must prepend a sub-opcode prefix.
type quicSender interface {
	Send(ctx context.Context, opcode byte, reqData, respData interface{}) error
	SendRequest(ctx context.Context, opcode byte, payload []byte) (*quicwire.Response, error)
	SendBoundRequest(ctx context.Context, opcode byte, build func(state *tls.ConnectionState) ([]byte, error)) (*quicwire.Response, error)
}

// realQUICSender wraps the concrete *quicwire.Client to satisfy quicSender.
type realQUICSender struct {
	client *quicwire.Client
}

func (s *realQUICSender) Send(ctx context.Context, opcode byte, reqData, respData interface{}) error {
	return s.client.Send(ctx, opcode, reqData, respData)
}

func (s *realQUICSender) SendRequest(ctx context.Context, opcode byte, payload []byte) (*quicwire.Response, error) {
	return s.client.SendRequest(ctx, opcode, payload)
}

func (s *realQUICSender) SendBoundRequest(ctx context.Context, opcode byte, build func(state *tls.ConnectionState) ([]byte, error)) (*quicwire.Response, error) {
	return s.client.SendBoundRequest(ctx, opcode, build)
}

// quicClientConn implements grpc.ClientConnInterface for QUIC transport.
// This allows using QUIC as a drop-in replacement for gRPC connections.
type quicClientConn struct {
	adapter *Adapter
	sender  quicSender
}

// methodRequestEncoder converts a pb request into the daemon's wire request
// for a non-category method whose request shape differs from the pb.
type methodRequestEncoder func(args interface{}) (interface{}, error)

// methodRequestEncoders routes non-category methods whose daemon request
// differs from the pb request. Methods absent from this map send the pb
// request as is; the codec pairs its fields with the daemon's by Go name.
var methodRequestEncoders = map[string]methodRequestEncoder{}

// Invoke performs a unary RPC call by translating to QUIC opcode requests.
// Category opcodes (overlay, gateway, IPAM, switch, tenant barrier, etc.)
// multiplex multiple operations under one wire opcode by stuffing the
// sub-opcode into payload[0] and the marshalled request into payload[1:].
// The server-side dispatchers (e.g. handleAppServiceCategory,
// handleTenantBarrierCategory) require this exact framing or they reject
// the request with ErrQUICMissingField{Field: "sub_opcode"}.
func (c *quicClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	// Validate method mapping first (request validation before infrastructure check)
	opcode, ok := grpcMethodToOpcodeMap[method]
	if !ok {
		return status.Error(codes.Unimplemented, ErrMethodNotMapped{Method: method}.Error())
	}

	// Check connection state
	if c.adapter.closed.Load() {
		return status.Error(codes.Unavailable, "connection closed")
	}

	if c.adapter.client == nil {
		return status.Error(codes.Unavailable, "client not initialized")
	}

	if c.sender == nil {
		c.sender = &realQUICSender{client: c.adapter.client}
	}

	// Category-opcode services require an explicit sub-opcode prefix on
	// the wire. For these methods we marshal the request ourselves,
	// prepend the sub-opcode byte, and use the raw-payload SendRequest
	// path so the prefix is preserved end-to-end.
	if isCategoryOpcode(opcode) {
		subOpcode, hasSubOpcode := categorySubOpcodeMap[method]
		if !hasSubOpcode {
			return status.Error(codes.Internal, ErrCategorySubOpcodeMissing{Method: method, Opcode: opcode}.Error())
		}

		// Empty-body sub-operations (e.g. provisioning get-nonce /
		// list-sessions) send only the sub-opcode byte on the wire even
		// though the generated gRPC client passes a non-nil empty request.
		payloadArgs := args
		if _, emptyBody := categoryEmptyBodyMethods[method]; emptyBody {
			payloadArgs = nil
		}
		if pager, paged := categoryPagers[method]; paged {
			return c.invokePaged(ctx, opcode, subOpcode, pager, args, reply, opts)
		}

		// A request its translator refuses never reaches the wire and is
		// the caller's InvalidArgument, as in wireRequest.
		if encode, translated := categoryRequestEncoders[method]; translated {
			wire, err := encode(args)
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
			payloadArgs = wire
		}

		resp, err := c.sendCategory(ctx, opcode, subOpcode, payloadArgs, opts)
		if err != nil {
			return err
		}

		if reply != nil && len(resp.Payload) > 0 {
			// Flattened-oneof responses (provisioning fetch-config /
			// poll-session) need a mirror-struct decode; everything else
			// decodes directly into the pb reply by Go field name.
			if decode, hasDecoder := categoryResponseDecoders[method]; hasDecoder {
				if decErr := decode(resp.Payload, reply); decErr != nil {
					return status.Error(codes.Internal, decErr.Error())
				}
				return nil
			}
			if decErr := quicwire.DecodePayload(resp.Payload, reply); decErr != nil {
				return status.Error(codes.Internal, ErrDecodingFailed{Err: decErr}.Error())
			}
		}
		return nil
	}

	// Standard non-category path. Methods whose request shape differs from
	// the daemon wire request encode through a method-specific encoder.
	// Methods whose reply shape differs from the daemon wire response
	// (Count* derived from List* pagination totals) decode through a
	// method-specific decoder; everything else decodes directly into the pb
	// reply by Go field name.
	// A call bound to its channel always takes the raw-payload path, so the
	// payload is encoded after the binding completes args.
	decode, hasDecoder := methodResponseDecoders[method]
	if _, bound := transport.ChannelBindingFrom(opts); bound && !hasDecoder {
		decode, hasDecoder = decodeReplyPayload, true
	}
	if hasDecoder {
		resp, err := c.sendRaw(ctx, opcode, encodeArgs(method, args), opts)
		if err != nil {
			return err
		}
		if reply != nil && len(resp.Payload) > 0 {
			if decErr := decode(resp.Payload, reply); decErr != nil {
				return status.Error(codes.Internal, decErr.Error())
			}
		}
		return nil
	}

	wire, err := wireRequest(method, args)
	if err != nil {
		return err
	}
	err = c.sender.Send(ctx, opcode, wire, reply)
	if err != nil {
		return translateQUICErrorToGRPC(err)
	}

	return nil
}

// sendCategory sends one category-opcode request: the sub-opcode byte
// followed by the encoded wire request.
func (c *quicClientConn) sendCategory(ctx context.Context, opcode, subOpcode byte, payloadArgs interface{}, opts []grpc.CallOption) (*quicwire.Response, error) {
	encode := func() ([]byte, error) {
		payload, err := buildCategoryPayload(subOpcode, payloadArgs)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return payload, nil
	}
	return c.sendRaw(ctx, opcode, encode, opts)
}

// invokePaged collects a paged category list into reply. It asks for the
// page after the entries already received until the daemon reports none
// left, so the caller gets the whole list, as over gRPC. A daemon that
// reports no total (one predating paging) answers in a single page.
func (c *quicClientConn) invokePaged(ctx context.Context, opcode, subOpcode byte, pager categoryPager, args, reply interface{}, opts []grpc.CallOption) error {
	var offset int32
	for {
		wire, err := pager.request(args, offset)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		resp, err := c.sendCategory(ctx, opcode, subOpcode, wire, opts)
		if err != nil {
			return err
		}
		page, err := pager.decode(resp.Payload, reply)
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		// int64, so a hostile total cannot wrap the remaining count.
		if page.received <= 0 || int64(page.received) >= int64(page.total)-int64(offset) {
			return nil
		}
		offset += page.received
	}
}

// sendRaw sends the payload encode builds and returns the response, with
// send failures already translated to gRPC status errors. A call bound to
// its channel (transport.WithChannelBinding) encodes only after handing the
// binding of the client's connection to the call's BindFunc, and the
// request travels on that same connection, so the proof the BindFunc adds
// to args is over the connection the daemon reads. Binding failures are
// returned as they are.
func (c *quicClientConn) sendRaw(ctx context.Context, opcode byte, encode func() ([]byte, error), opts []grpc.CallOption) (*quicwire.Response, error) {
	bind, bound := transport.ChannelBindingFrom(opts)
	if !bound {
		payload, err := encode()
		if err != nil {
			return nil, err
		}
		resp, err := c.sender.SendRequest(ctx, opcode, payload)
		if err != nil {
			return nil, translateQUICErrorToGRPC(err)
		}
		return resp, nil
	}

	var buildErr error
	resp, err := c.sender.SendBoundRequest(ctx, opcode, func(state *tls.ConnectionState) ([]byte, error) {
		if err := transport.BindChannel(ctx, platform.ProtocolQUIC.String(), state, bind); err != nil {
			buildErr = err
			return nil, err
		}
		var payload []byte
		payload, buildErr = encode()
		return payload, buildErr
	})
	if buildErr != nil {
		return nil, buildErr
	}
	if err != nil {
		return nil, translateQUICErrorToGRPC(err)
	}
	return resp, nil
}

// wireRequest returns the daemon wire request for args: the result of the
// method's request encoder when it has one, args itself otherwise.
func wireRequest(method string, args interface{}) (interface{}, error) {
	encode, hasEncoder := methodRequestEncoders[method]
	if !hasEncoder {
		return args, nil
	}
	wire, err := encode(args)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return wire, nil
}

// encodeArgs returns an encoder for the method's wire request in the
// protocol codec. The wire request is built when the encoder runs, so a
// channel binding has already completed args.
func encodeArgs(method string, args interface{}) func() ([]byte, error) {
	return func() ([]byte, error) {
		wire, err := wireRequest(method, args)
		if err != nil {
			return nil, err
		}
		payload, err := quicwire.EncodePayload(wire)
		if err != nil {
			return nil, status.Error(codes.Internal, ErrEncodingFailed{Err: err}.Error())
		}
		return payload, nil
	}
}

// decodeReplyPayload decodes a response payload straight into the reply,
// as Send does for unbound calls.
func decodeReplyPayload(payload []byte, reply interface{}) error {
	if err := quicwire.DecodePayload(payload, reply); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	return nil
}

// buildCategoryPayload marshals args via the protocol codec and prepends
// the sub-opcode byte expected by category-opcode dispatchers. Nil args
// are encoded as a one-byte payload containing only the sub-opcode,
// which mirrors the server-side decode path that treats payload[1:] as
// the optional sub-request body.
func buildCategoryPayload(subOpcode byte, args interface{}) ([]byte, error) {
	if args == nil {
		return []byte{subOpcode}, nil
	}

	encoded, err := quicwire.EncodePayload(args)
	if err != nil {
		return nil, ErrEncodingFailed{Err: err}
	}

	out := make([]byte, 0, 1+len(encoded))
	out = append(out, subOpcode)
	out = append(out, encoded...)
	return out, nil
}

// isCategoryOpcode reports whether opcode is one of the well-known
// category opcodes that multiplex sub-operations via payload[0].
func isCategoryOpcode(opcode byte) bool {
	_, ok := categoryOpcodes[opcode]
	return ok
}

// categoryOpcodes is the canonical set of QUIC category opcodes whose
// server-side handlers expect payload[0] to be the sub-opcode and
// payload[1:] to be the sub-request body. Any opcode added here MUST
// have a matching server-side dispatcher in pkg/api/daemon and every
// gRPC method routed to it MUST appear in categorySubOpcodeMap.
var categoryOpcodes = map[byte]struct{}{
	quicwire.OpOverlayCategory:       {},
	quicwire.OpGatewayCategory:       {},
	quicwire.OpIPAMCategory:          {},
	quicwire.OpTPM2Category:          {},
	quicwire.OpCeremonyCategory:      {},
	quicwire.OpPIVCategory:           {},
	quicwire.OpLUKSCategory:          {},
	quicwire.OpFIDO2Category:         {},
	quicwire.OpTenantBarrierCategory: {},
	quicwire.OpSwitchCategory:        {},
	quicwire.OpProvisioningCategory:  {},
	quicwire.OpVMExtendedCategory:    {},
	quicwire.OpKMSExtendedCategory:   {},
}

// categorySubOpcodeMap routes gRPC method paths to the sub-opcode byte
// that the server-side category dispatcher expects in payload[0].
//
// Every entry in grpcMethodToOpcodeMap whose value appears in
// categoryOpcodes MUST have a corresponding entry here. The package
// init function asserts this invariant at startup so a missing mapping
// is caught at process start, not at first request.
var categorySubOpcodeMap = map[string]byte{
	// Ceremony Service — OpCeremonyCategory (0x9A)
	// Server dispatcher: pkg/api/daemon/phase35_quic.go::ceremonyQUICDispatch
	"/platform.v1.CeremonyService/Init":               quicwire.CeremonySubInit,
	"/platform.v1.CeremonyService/Status":             quicwire.CeremonySubStatus,
	"/platform.v1.CeremonyService/ClaimCertBegin":     quicwire.CeremonySubClaimCertBegin,
	"/platform.v1.CeremonyService/ClaimCertComplete":  quicwire.CeremonySubClaimCertComplete,
	"/platform.v1.CeremonyService/ClaimShareBegin":    quicwire.CeremonySubClaimShareBegin,
	"/platform.v1.CeremonyService/ClaimShareComplete": quicwire.CeremonySubClaimShareComplete,
	"/platform.v1.CeremonyService/SignCSR":            quicwire.CeremonySubSignCSR,

	// TPM Service — OpTPM2Category (0x99)
	// Server dispatcher: pkg/api/quic/tpm_handlers.go::TPM2Handler; codecs in
	// tpm_quote.go (#482).
	"/platform.v1.TPMService/Quote":       quicwire.SubOpTPM2Quote,
	"/platform.v1.TPMService/VerifyQuote": quicwire.SubOpTPM2VerifyQuote,
	"/platform.v1.TPMService/Certify":     quicwire.SubOpTPM2Certify,

	// PIV Service — OpPIVCategory (0x9B)
	// Server dispatcher: pkg/api/daemon/phase35_quic.go::pivQUICDispatch
	"/platform.v1.PIVService/ListDevices": quicwire.PIVSubListDevices,
	"/platform.v1.PIVService/ListSlots":   quicwire.PIVSubListSlots,
	"/platform.v1.PIVService/SlotInfo":    quicwire.PIVSubSlotInfo,
	"/platform.v1.PIVService/Generate":    quicwire.PIVSubGenerate,
	"/platform.v1.PIVService/Import":      quicwire.PIVSubImport,
	"/platform.v1.PIVService/Sign":        quicwire.PIVSubSign,
	"/platform.v1.PIVService/Attest":      quicwire.PIVSubAttest,
	"/platform.v1.PIVService/Reset":       quicwire.PIVSubReset,

	// LUKS Service — OpLUKSCategory (0x9C)
	// Server dispatcher: pkg/api/daemon/phase35_quic.go::luksQUICDispatch
	"/platform.v1.LUKSService/Status":           quicwire.LUKSSubStatus,
	"/platform.v1.LUKSService/ListSlots":        quicwire.LUKSSubListSlots,
	"/platform.v1.LUKSService/Info":             quicwire.LUKSSubInfo,
	"/platform.v1.LUKSService/EnrollPassphrase": quicwire.LUKSSubEnrollPassphrase,
	"/platform.v1.LUKSService/EnrollFIDO2":      quicwire.LUKSSubEnrollFIDO2,
	"/platform.v1.LUKSService/EnrollTPM":        quicwire.LUKSSubEnrollTPM,
	"/platform.v1.LUKSService/EnrollRecovery":   quicwire.LUKSSubEnrollRecovery,
	"/platform.v1.LUKSService/RemoveKey":        quicwire.LUKSSubRemoveKey,
	"/platform.v1.LUKSService/TestUnlock":       quicwire.LUKSSubTestUnlock,
	"/platform.v1.LUKSService/ChangePassphrase": quicwire.LUKSSubChangePassphrase,

	// FIDO2 Service — OpFIDO2Category (0x9D)
	// Server dispatcher: pkg/api/daemon/phase35_quic.go::fido2QUICDispatch
	"/platform.v1.FIDO2Service/ListDevices":  quicwire.FIDO2SubListDevices,
	"/platform.v1.FIDO2Service/WaitDevice":   quicwire.FIDO2SubWaitDevice,
	"/platform.v1.FIDO2Service/Info":         quicwire.FIDO2SubInfo,
	"/platform.v1.FIDO2Service/Register":     quicwire.FIDO2SubRegister,
	"/platform.v1.FIDO2Service/Authenticate": quicwire.FIDO2SubAuthenticate,

	// Switch Service — OpSwitchCategory (0xCC)
	// Server dispatcher: pkg/api/daemon/quic_switch.go::switchQUICHandlers
	"/platform.v1.SwitchService/ListPorts":     quicwire.SwitchSubListPorts,
	"/platform.v1.SwitchService/GetPortStatus": quicwire.SwitchSubGetPortStatus,
	"/platform.v1.SwitchService/SetPortVLAN":   quicwire.SwitchSubSetPortVLAN,
	"/platform.v1.SwitchService/EnablePort":    quicwire.SwitchSubEnablePort,
	"/platform.v1.SwitchService/DisablePort":   quicwire.SwitchSubDisablePort,

	// Compute Service containers — OpVMExtendedCategory (0x69) sub-opcodes.
	// Server dispatcher: pkg/api/daemon/quic_vm.go::handleVMServiceOperation
	"/platform.v1.ComputeService/CreateContainer": quicwire.OpContainerCreate,
	"/platform.v1.ComputeService/StartContainer":  quicwire.OpContainerStart,
	"/platform.v1.ComputeService/StopContainer":   quicwire.OpContainerStop,
	"/platform.v1.ComputeService/DeleteContainer": quicwire.OpContainerRemove,
	"/platform.v1.ComputeService/GetContainer":    quicwire.OpContainerGet,
	"/platform.v1.ComputeService/ListContainers":  quicwire.OpContainerList,

	// Compute Service operational VM verbs — OpVMExtendedCategory (0x69) sub-opcodes.
	// Server dispatcher: pkg/api/daemon/quic_vm_pb.go::handleVMPB
	"/platform.v1.ComputeService/GetVMMetrics": quicwire.OpVMMetrics,
	"/platform.v1.ComputeService/AttachDisk":   quicwire.OpVMAttachDisk,
	"/platform.v1.ComputeService/DetachDisk":   quicwire.OpVMDetachDisk,
	"/platform.v1.ComputeService/ResizeDisk":   quicwire.OpVMResizeDisk,
	"/platform.v1.ComputeService/MigrateVM":    quicwire.OpVMMigrate,

	// Tenant Service — OpTenantBarrierCategory (0x9E)
	// Server dispatcher: pkg/api/daemon/quic_tenant.go::handleTenantBarrierCategory
	"/platform.v1.TenantService/InitTenantBarrier":      quicwire.TenantBarrierSubInit,
	"/platform.v1.TenantService/UnsealTenantBarrier":    quicwire.TenantBarrierSubUnseal,
	"/platform.v1.TenantService/SealTenantBarrier":      quicwire.TenantBarrierSubSeal,
	"/platform.v1.TenantService/GetTenantBarrierStatus": quicwire.TenantBarrierSubStatus,

	// Config Delivery Service — OpProvisioningCategory (0xCF)
	// Server dispatcher: pkg/api/daemon/quic_configdelivery.go::handleProvisioningCategory
	"/platform.v1.ConfigDeliveryService/GetNonce":       quicwire.ProvisioningSubGetNonce,
	"/platform.v1.ConfigDeliveryService/FetchConfig":    quicwire.ProvisioningSubFetchConfig,
	"/platform.v1.ConfigDeliveryService/SignDigest":     quicwire.ProvisioningSubSignDigest,
	"/platform.v1.ConfigDeliveryService/PollSession":    quicwire.ProvisioningSubPollSession,
	"/platform.v1.ConfigDeliveryService/FulfillSession": quicwire.ProvisioningSubFulfillSession,
	"/platform.v1.ConfigDeliveryService/ListSessions":   quicwire.ProvisioningSubListSessions,
	"/platform.v1.ConfigDeliveryService/GetSession":     quicwire.ProvisioningSubGetSession,

	// EAB Service — multiplexed under OpProvisioningCategory (0xCF),
	// sub-range 0x10-0x1A (the single-byte opcode space is fully
	// allocated). Server dispatcher:
	// pkg/api/daemon/quic_eab.go::handleEABCategorySub
	"/platform.v1.EABService/CreateCredential":          quicwire.EABSubCreateCredential,
	"/platform.v1.EABService/GetCredential":             quicwire.EABSubGetCredential,
	"/platform.v1.EABService/GetCredentialByKeyID":      quicwire.EABSubGetCredentialByKeyID,
	"/platform.v1.EABService/ListCredentials":           quicwire.EABSubListCredentials,
	"/platform.v1.EABService/RevokeCredential":          quicwire.EABSubRevokeCredential,
	"/platform.v1.EABService/ValidateCredential":        quicwire.EABSubValidateCredential,
	"/platform.v1.EABService/DeleteCredential":          quicwire.EABSubDeleteCredential,
	"/platform.v1.EABService/GetCredentialQRCode":       quicwire.EABSubGetCredentialQRCode,
	"/platform.v1.EABService/GetEnrollmentURL":          quicwire.EABSubGetEnrollmentURL,
	"/platform.v1.EABService/MarkCredentialUsed":        quicwire.EABSubMarkCredentialUsed,
	"/platform.v1.EABService/CleanupExpiredCredentials": quicwire.EABSubCleanupExpiredCredentials,

	// Device profile assignment — multiplexed under
	// OpProvisioningCategory (0xCF), sub-range 0x20-0x2F. Server
	// dispatcher: pkg/api/daemon/quic_device_handlers.go::
	// handleDeviceProfileCategorySub
	"/platform.v1.DeviceService/AssignProfileToDevice":     quicwire.DeviceProfileSubAssign,
	"/platform.v1.DeviceService/UnassignProfileFromDevice": quicwire.DeviceProfileSubUnassign,
	// Attestation certificate record verb (#473): same category, sub-opcode
	// 0x22. Server dispatcher: handleDeviceProfileCategorySub ->
	// handleDeviceRecordAttestCert.
	"/platform.v1.DeviceService/RecordAttestationCertificate": quicwire.DeviceSubRecordAttestCert,
	// A diskless node's per-boot requests: sub-opcodes 0x23 and 0x24, which
	// the server serves without a token (the node holds none).
	"/platform.v1.DeviceService/BootCertificate": quicwire.DeviceSubBootCertificate,
	"/platform.v1.DeviceService/BootDelivery":    quicwire.DeviceSubBootDelivery,

	// Operator Enable/Disable Device (#250): sub-opcodes 0x25 and 0x26 of
	// the same category. Server dispatcher: handleDeviceProfileCategorySub
	// -> handleDeviceDisable / handleDeviceEnable.
	"/platform.v1.DeviceService/DisableDevice": quicwire.DeviceSubDisable,
	"/platform.v1.DeviceService/EnableDevice":  quicwire.DeviceSubEnable,

	// Device templates: handleDeviceTemplateCreate and
	// handleDeviceProfileFromTemplate.
	"/platform.v1.DeviceService/CreateTemplate":            quicwire.DeviceSubTemplateCreate,
	"/platform.v1.DeviceService/CreateProfileFromTemplate": quicwire.DeviceSubProfileFromTemplate,

	// Profile matching: handleDeviceFindMatchingProfile.
	"/platform.v1.DeviceService/FindMatchingProfile": quicwire.DeviceSubFindMatchingProfile,

	// Proxy Service — multiplexed under OpGatewayCategory (0x2F),
	// sub-range 0x20-0x2D (the single-byte opcode space is fully
	// allocated). Server dispatcher:
	// pkg/api/daemon/quic_service.go::handleGatewayCategory routes the
	// proxy sub-range to pkg/api/quic/proxy_handlers.go::ProxyHandler.
	"/platform.v1.ProxyService/CreateRoute":       quicwire.ProxySubRouteCreate,
	"/platform.v1.ProxyService/GetRoute":          quicwire.ProxySubRouteGet,
	"/platform.v1.ProxyService/UpdateRoute":       quicwire.ProxySubRouteUpdate,
	"/platform.v1.ProxyService/DeleteRoute":       quicwire.ProxySubRouteDelete,
	"/platform.v1.ProxyService/ListRoutes":        quicwire.ProxySubRouteList,
	"/platform.v1.ProxyService/CreatePool":        quicwire.ProxySubPoolCreate,
	"/platform.v1.ProxyService/GetPool":           quicwire.ProxySubPoolGet,
	"/platform.v1.ProxyService/UpdatePool":        quicwire.ProxySubPoolUpdate,
	"/platform.v1.ProxyService/DeletePool":        quicwire.ProxySubPoolDelete,
	"/platform.v1.ProxyService/ListPools":         quicwire.ProxySubPoolList,
	"/platform.v1.ProxyService/GetProxyConfig":    quicwire.ProxySubConfigGet,
	"/platform.v1.ProxyService/GetProxyStatus":    quicwire.ProxySubStatusGet,
	"/platform.v1.ProxyService/ReloadProxyConfig": quicwire.ProxySubReload,
	"/platform.v1.ProxyService/GetZoneMatrix":     quicwire.ProxySubZoneMatrix,

	// Gateway perf verification — multiplexed under OpGatewayCategory
	// (0x2F), sub-range 0x36-0x38 (gateway 0x00-0x14, proxy 0x20-0x2D,
	// load balancer 0x30-0x35). Server dispatcher:
	// pkg/api/daemon/quic_service.go::handleGatewayCategory routes the
	// sub-opcodes to pkg/api/quic/gateway_perf_handlers.go.
	"/platform.v1.GatewayService/GetPerfFlows":     quicwire.OpGatewayPerfFlows,
	"/platform.v1.GatewayService/GetPerfDatapath":  quicwire.OpGatewayPerfDatapath,
	"/platform.v1.GatewayService/GetPerfConntrack": quicwire.OpGatewayPerfConntrack,

	// NAT64 translator status — sub-opcode 0x39, next after the perf
	// range. Server dispatcher: pkg/api/quic/gateway_nat64_handlers.go.
	"/platform.v1.GatewayService/GetNAT64Status": quicwire.OpGatewayNAT64Status,

	// Gateway status, mode set and IPAM — the gateway range 0x01-0x0F.
	// Requests and replies use the quicwire shapes the server handler
	// speaks (gateway_status_ipam.go converts them).
	"/platform.v1.GatewayService/GetGatewayStatus": quicwire.OpGatewayStatus,
	"/platform.v1.GatewayService/SetGatewayMode":   quicwire.OpGatewaySetMode,
	"/platform.v1.GatewayService/ListIPAMPools":    quicwire.OpGatewayListIPAMPools,
	"/platform.v1.GatewayService/GetIPAMPool":      quicwire.OpGatewayGetIPAMPool,
	"/platform.v1.GatewayService/CreateIPAMPool":   quicwire.OpGatewayCreateIPAMPool,
	"/platform.v1.GatewayService/UpdateIPAMPool":   quicwire.OpGatewayUpdateIPAMPool,
	"/platform.v1.GatewayService/DeleteIPAMPool":   quicwire.OpGatewayDeleteIPAMPool,
	"/platform.v1.GatewayService/AllocateIP":       quicwire.OpGatewayAllocateIP,
	"/platform.v1.GatewayService/ReleaseIP":        quicwire.OpGatewayReleaseIP,
	"/platform.v1.GatewayService/ListAllocations":  quicwire.OpGatewayListAllocations,

	// BGP speaker — shapes and conversions in gateway_bgp.go.
	"/platform.v1.GatewayService/GetBGPStatus":          quicwire.OpGatewayBGPStatus,
	"/platform.v1.GatewayService/ListBGPPeers":          quicwire.OpGatewayBGPPeers,
	"/platform.v1.GatewayService/AnnouncePrefix":        quicwire.OpGatewayAnnouncePrefix,
	"/platform.v1.GatewayService/WithdrawPrefix":        quicwire.OpGatewayWithdrawPrefix,
	"/platform.v1.GatewayService/ListAnnouncedPrefixes": quicwire.OpGatewayListPrefixes,

	// Admitted overlay VTEPs — read from the gateway telemetry snapshot.
	// Server dispatcher: pkg/api/quic/gateway_handlers.go; requests and
	// responses are translated in gateway_admitted_vtep.go.
	"/platform.v1.GatewayService/GetGatewayAdmittedVTEP":   quicwire.OpGatewayAdmittedVTEP,
	"/platform.v1.GatewayService/ListGatewayAdmittedVTEPs": quicwire.OpGatewayListAdmittedVTEPs,

	// CA CSR signing — multiplexed under OpKMSExtendedCategory (0xCD),
	// because it certifies an existing KMS key and the opcode space is
	// fully allocated. Server dispatcher:
	// pkg/api/daemon/quic_kms_extended.go::handleKMSExtendedCategory.
	"/platform.v1.CAService/SignCSR": quicwire.KMSSubSignCSR,
}

// init asserts the cross-table invariant: every gRPC method whose
// resolved opcode is a category opcode must have a sub-opcode mapping.
// A missing entry would silently send a zero-byte sub-opcode and trip
// the server's StatusNotImplemented branch on the first call.
func init() {
	for method, opcode := range grpcMethodToOpcodeMap {
		if _, isCat := categoryOpcodes[opcode]; !isCat {
			continue
		}
		if _, hasSub := categorySubOpcodeMap[method]; !hasSub {
			panic(ErrCategorySubOpcodeMissing{Method: method, Opcode: opcode}.Error())
		}
	}
}

// grpcMethodToOpcodeMap provides O(1) lookup for gRPC method to QUIC opcode mapping.
// Method paths use the proto package "platform.v1" (with dot) and full RPC
// names that exactly match the generated gRPC stubs in sdk/go/gen.
// The QUIC server side dispatches requests by opcode in pkg/api/daemon/quic_service.go.
var grpcMethodToOpcodeMap = map[string]byte{
	// CA Service — proto: pkg/api/grpc/proto/ca.proto
	"/platform.v1.CAService/GetCAInfo":         quicwire.OpCAInfo,
	"/platform.v1.CAService/IssueCertificate":  quicwire.OpCAIssue,
	"/platform.v1.CAService/SignCSR":           quicwire.OpKMSExtendedCategory,
	"/platform.v1.CAService/GetCertificate":    quicwire.OpCAGet,
	"/platform.v1.CAService/ListCertificates":  quicwire.OpCAList,
	"/platform.v1.CAService/RevokeCertificate": quicwire.OpCARevoke,
	"/platform.v1.CAService/RenewCertificate":  quicwire.OpCARenew,
	"/platform.v1.CAService/VerifyCertificate": quicwire.OpCAVerify,
	"/platform.v1.CAService/GetCRL":            quicwire.OpCACRL,
	"/platform.v1.CAService/GetCABundle":       quicwire.OpCABundle,

	// IAM User Operations — proto: pkg/api/grpc/proto/iam.proto
	"/platform.v1.PlatformIAMService/CreateUser": quicwire.OpIAMUserCreate,
	"/platform.v1.PlatformIAMService/DeleteUser": quicwire.OpIAMUserDelete,
	"/platform.v1.PlatformIAMService/GetUser":    quicwire.OpIAMUserGet,
	"/platform.v1.PlatformIAMService/ListUsers":  quicwire.OpIAMUserList,
	"/platform.v1.PlatformIAMService/UpdateUser": quicwire.OpIAMUserUpdate,

	// IAM Role Operations
	"/platform.v1.PlatformIAMService/CreateRole": quicwire.OpIAMRoleCreate,
	"/platform.v1.PlatformIAMService/DeleteRole": quicwire.OpIAMRoleDelete,
	"/platform.v1.PlatformIAMService/GetRole":    quicwire.OpIAMRoleGet,
	"/platform.v1.PlatformIAMService/ListRoles":  quicwire.OpIAMRoleList,
	"/platform.v1.PlatformIAMService/AssignRole": quicwire.OpIAMRoleAssign,
	"/platform.v1.PlatformIAMService/RevokeRole": quicwire.OpIAMRoleRevoke,

	// IAM Group Operations
	"/platform.v1.PlatformIAMService/CreateGroup":       quicwire.OpIAMGroupCreate,
	"/platform.v1.PlatformIAMService/DeleteGroup":       quicwire.OpIAMGroupDelete,
	"/platform.v1.PlatformIAMService/GetGroup":          quicwire.OpIAMGroupGet,
	"/platform.v1.PlatformIAMService/ListGroups":        quicwire.OpIAMGroupList,
	"/platform.v1.PlatformIAMService/AddGroupMember":    quicwire.OpIAMGroupAddMember,
	"/platform.v1.PlatformIAMService/RemoveGroupMember": quicwire.OpIAMGroupRemoveMember,

	// IAM tenant records route to OpIAMCategory (aab_iam_tenant.go), never to
	// the platform tenancy opcodes below (#767).

	// IAM Token / Auth Operations
	"/platform.v1.PlatformIAMService/CheckPermission": quicwire.OpIAMCheckPermission,
	"/platform.v1.PlatformIAMService/CreateToken":     quicwire.OpIAMTokenCreate,
	"/platform.v1.PlatformIAMService/RevokeToken":     quicwire.OpIAMTokenRevoke,
	"/platform.v1.PlatformIAMService/VerifyToken":     quicwire.OpIAMTokenVerify,

	// KMS Key Management — proto: pkg/api/grpc/proto/kms.proto
	"/platform.v1.KeyManagementService/GenerateKey":            quicwire.OpKMSGenerateKey,
	"/platform.v1.KeyManagementService/ImportKey":              quicwire.OpKMSImportKey,
	"/platform.v1.KeyManagementService/GetKey":                 quicwire.OpKMSGetKey,
	"/platform.v1.KeyManagementService/ListKeys":               quicwire.OpKMSListKeys,
	"/platform.v1.KeyManagementService/DeleteKey":              quicwire.OpKMSDeleteKey,
	"/platform.v1.KeyManagementService/RotateKey":              quicwire.OpKMSRotateKey,
	"/platform.v1.KeyManagementService/UpdateKeyStatus":        quicwire.OpKMSUpdateKeyStatus,
	"/platform.v1.KeyManagementService/ExportKey":              quicwire.OpKMSExportKey,
	"/platform.v1.KeyManagementService/GetKeyVersions":         quicwire.OpKMSGetKeyVersions,
	"/platform.v1.KeyManagementService/BackendStatus":          quicwire.OpKMSBackendStatus,
	"/platform.v1.KeyManagementService/Encrypt":                quicwire.OpKMSEncrypt,
	"/platform.v1.KeyManagementService/Decrypt":                quicwire.OpKMSDecrypt,
	"/platform.v1.KeyManagementService/BatchEncrypt":           quicwire.OpKMSBatchEncrypt,
	"/platform.v1.KeyManagementService/BatchDecrypt":           quicwire.OpKMSBatchDecrypt,
	"/platform.v1.KeyManagementService/Rewrap":                 quicwire.OpKMSRewrap,
	"/platform.v1.KeyManagementService/Sign":                   quicwire.OpKMSSign,
	"/platform.v1.KeyManagementService/Verify":                 quicwire.OpKMSVerify,
	"/platform.v1.KeyManagementService/GenerateRandom":         quicwire.OpKMSGenerateRandom,
	"/platform.v1.KeyManagementService/Hash":                   quicwire.OpKMSHash,
	"/platform.v1.KeyManagementService/HMAC":                   quicwire.OpKMSHMAC,
	"/platform.v1.KeyManagementService/VerifyHMAC":             quicwire.OpKMSVerifyHMAC,
	"/platform.v1.KeyManagementService/GenerateDataKey":        quicwire.OpKMSGenerateDataKey,
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": quicwire.OpKMSGenerateWrappedDataKey,

	// vTPM Service — proto: pkg/api/grpc/proto/vtpm.proto
	"/platform.v1.VTPMService/QuoteVTPM":     quicwire.OpVTPMQuote,
	"/platform.v1.VTPMService/SealVTPM":      quicwire.OpVTPMSeal,
	"/platform.v1.VTPMService/UnsealVTPM":    quicwire.OpVTPMUnseal,
	"/platform.v1.VTPMService/ExtendVTPMPCR": quicwire.OpVTPMExtendPCR,
	"/platform.v1.VTPMService/ReadVTPMPCR":   quicwire.OpVTPMReadPCR,

	// TPM Service — proto: pkg/api/grpc/proto/tpm.proto; category-routed
	"/platform.v1.TPMService/Quote":       quicwire.OpTPM2Category,
	"/platform.v1.TPMService/VerifyQuote": quicwire.OpTPM2Category,
	"/platform.v1.TPMService/Certify":     quicwire.OpTPM2Category,

	// Device Service — proto: pkg/api/grpc/proto/device.proto
	"/platform.v1.DeviceService/CreateDevice":       quicwire.OpDeviceRegister,
	"/platform.v1.DeviceService/DeleteDevice":       quicwire.OpDeviceUnregister,
	"/platform.v1.DeviceService/GetDevice":          quicwire.OpDeviceGet,
	"/platform.v1.DeviceService/ListDevices":        quicwire.OpDeviceList,
	"/platform.v1.DeviceService/UpdateDevice":       quicwire.OpDeviceUpdate,
	"/platform.v1.DeviceService/ActivateDevice":     quicwire.OpDeviceActivate,
	"/platform.v1.DeviceService/CountDevices":       quicwire.OpDeviceList,
	"/platform.v1.DeviceService/FindDeviceBySerial": quicwire.OpDeviceGet,
	"/platform.v1.DeviceService/CreateProfile":      quicwire.OpDeviceCreateProfile,
	"/platform.v1.DeviceService/GetProfile":         quicwire.OpDeviceGetProfile,
	"/platform.v1.DeviceService/ListProfiles":       quicwire.OpDeviceListProfiles,
	"/platform.v1.DeviceService/CountProfiles":      quicwire.OpDeviceListProfiles,
	"/platform.v1.DeviceService/UpdateProfile":      quicwire.OpDeviceSetProfile,
	"/platform.v1.DeviceService/DeleteProfile":      quicwire.OpDeviceDeleteProfile,
	// Profile assignment travels as sub-opcodes under
	// OpProvisioningCategory because the single-byte opcode space is
	// fully allocated. See categorySubOpcodeMap and
	// pkg/api/daemon/quic_device_handlers.go.
	"/platform.v1.DeviceService/AssignProfileToDevice":        quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/UnassignProfileFromDevice":    quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/RecordAttestationCertificate": quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/BootCertificate":              quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/BootDelivery":                 quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/DisableDevice":                quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/EnableDevice":                 quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/CreateTemplate":               quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/CreateProfileFromTemplate":    quicwire.OpProvisioningCategory,
	"/platform.v1.DeviceService/FindMatchingProfile":          quicwire.OpProvisioningCategory,

	// SDN Service — proto: pkg/api/grpc/proto/sdn.proto
	"/platform.v1.SDNService/CreateBridge": quicwire.OpSDNCreateBridge,
	"/platform.v1.SDNService/DeleteBridge": quicwire.OpSDNDeleteBridge,
	"/platform.v1.SDNService/ListBridges":  quicwire.OpSDNListBridges,
	"/platform.v1.SDNService/GetBridge":    quicwire.OpSDNGetBridge,
	"/platform.v1.SDNService/GetPort":      quicwire.OpSDNGetPort,
	"/platform.v1.SDNService/SetPortState": quicwire.OpSDNSetPortState,
	"/platform.v1.SDNService/AddPort":      quicwire.OpSDNCreatePort,
	"/platform.v1.SDNService/DeletePort":   quicwire.OpSDNDeletePort,
	"/platform.v1.SDNService/ListPorts":    quicwire.OpSDNListPorts,
	"/platform.v1.SDNService/AddFlow":      quicwire.OpSDNAddFlow,
	"/platform.v1.SDNService/DeleteFlow":   quicwire.OpSDNDeleteFlow,
	"/platform.v1.SDNService/ListFlows":    quicwire.OpSDNListFlows,

	// DNS Service — proto: pkg/api/grpc/proto/platform_dns.proto
	"/platform.v1.DNSService/AddRecord":    quicwire.OpDNSAddRecord,
	"/platform.v1.DNSService/DeleteRecord": quicwire.OpDNSDeleteRecord,
	"/platform.v1.DNSService/ListRecords":  quicwire.OpDNSListRecords,
	"/platform.v1.DNSService/Resolve":      quicwire.OpDNSResolve,
	"/platform.v1.DNSService/CreateZone":   quicwire.OpDNSAddZone,
	"/platform.v1.DNSService/DeleteZone":   quicwire.OpDNSDeleteZone,
	"/platform.v1.DNSService/ListZones":    quicwire.OpDNSListZones,

	// Attestation Service — proto: pkg/api/grpc/proto/attestation.proto
	"/platform.v1.AttestationService/GetAttestationQuote":    quicwire.OpAttestQuote,
	"/platform.v1.AttestationService/VerifyAttestationQuote": quicwire.OpAttestVerify,
	"/platform.v1.AttestationService/CollectHostAttestation": quicwire.OpAttestCollectHost,
	"/platform.v1.AttestationService/PollDeviceVerdicts":     quicwire.OpAttestPollVerdicts,

	// IDevID Service — proto: pkg/api/grpc/proto/idevid.proto
	"/platform.v1.IDevIDService/GetIDevID":                quicwire.OpIDevIDInfo,
	"/platform.v1.IDevIDService/DeleteIDevID":             quicwire.OpIDevIDDelete,
	"/platform.v1.IDevIDService/CreateIDevIDCSR":          quicwire.OpIDevIDCSR,
	"/platform.v1.IDevIDService/InstallIDevIDCertificate": quicwire.OpIDevIDInstallCert,
	"/platform.v1.IDevIDService/GetIDevIDCertificate":     quicwire.OpIDevIDGetCert,

	// IAK (under IDevIDService)
	"/platform.v1.IDevIDService/GetIAK":                quicwire.OpIAKInfo,
	"/platform.v1.IDevIDService/DeleteIAK":             quicwire.OpIAKDelete,
	"/platform.v1.IDevIDService/CreateIAKCSR":          quicwire.OpIAKCSR,
	"/platform.v1.IDevIDService/InstallIAKCertificate": quicwire.OpIAKInstallCert,
	"/platform.v1.IDevIDService/GetIAKCertificate":     quicwire.OpIAKGetCert,

	// Tenant Service — proto: pkg/api/grpc/proto/tenant.proto
	"/platform.v1.TenantService/CreateTenant":       quicwire.OpTenantCreate,
	"/platform.v1.TenantService/DeleteTenant":       quicwire.OpTenantDelete,
	"/platform.v1.TenantService/GetTenant":          quicwire.OpTenantGet,
	"/platform.v1.TenantService/GetTenantByName":    quicwire.OpTenantGetByName,
	"/platform.v1.TenantService/ListTenants":        quicwire.OpTenantList,
	"/platform.v1.TenantService/UpdateTenant":       quicwire.OpTenantUpdate,
	"/platform.v1.TenantService/SuspendTenant":      quicwire.OpTenantSuspend,
	"/platform.v1.TenantService/ResumeTenant":       quicwire.OpTenantResume,
	"/platform.v1.TenantService/GetQuotas":          quicwire.OpTenantGetQuotas,
	"/platform.v1.TenantService/UpdateQuotas":       quicwire.OpTenantUpdateQuotas,
	"/platform.v1.TenantService/GetUsage":           quicwire.OpTenantGetUsage,
	"/platform.v1.TenantService/CheckQuota":         quicwire.OpTenantCheckQuota,
	"/platform.v1.TenantService/Sync":               quicwire.OpTenantSync,
	"/platform.v1.TenantService/RotateTenantDEK":    quicwire.OpTenantRotateDEK,
	"/platform.v1.TenantService/GetTenantDEKStatus": quicwire.OpTenantGetDEKStatus,
	// Per-tenant barrier ops share OpTenantBarrierCategory and dispatch via
	// payload[0] on the server (pkg/api/daemon/quic_tenant.go::handleTenantBarrierCategory).
	// The SDK adapter prepends the sub-opcode automatically; see
	// categorySubOpcodeMap above.
	"/platform.v1.TenantService/InitTenantBarrier":      quicwire.OpTenantBarrierCategory,
	"/platform.v1.TenantService/UnsealTenantBarrier":    quicwire.OpTenantBarrierCategory,
	"/platform.v1.TenantService/SealTenantBarrier":      quicwire.OpTenantBarrierCategory,
	"/platform.v1.TenantService/GetTenantBarrierStatus": quicwire.OpTenantBarrierCategory,

	// Config Delivery Service — proto: pkg/api/grpc/proto/configdelivery.proto
	// All ConfigDeliveryService methods route to OpProvisioningCategory
	// (0xCF); the SDK adapter prepends the sub-opcode automatically. See
	// categorySubOpcodeMap and pkg/api/daemon/quic_configdelivery.go.
	"/platform.v1.ConfigDeliveryService/GetNonce":       quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/FetchConfig":    quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/SignDigest":     quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/PollSession":    quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/FulfillSession": quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/ListSessions":   quicwire.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/GetSession":     quicwire.OpProvisioningCategory,

	// EAB Service — proto: pkg/api/grpc/proto/eab.proto
	// All EABService methods route to OpProvisioningCategory (0xCF) via
	// the EAB sub-opcode range 0x10-0x1A; the SDK adapter prepends the
	// sub-opcode automatically. See categorySubOpcodeMap,
	// sdk/go/wire/quicwire/eab_opcodes.go and pkg/api/daemon/quic_eab.go.
	// All ProxyService methods route to OpGatewayCategory (0x2F) via
	// proxy sub-opcodes 0x20-0x2D (see categorySubOpcodeMap above).
	"/platform.v1.ProxyService/CreateRoute":       quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/GetRoute":          quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/UpdateRoute":       quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/DeleteRoute":       quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/ListRoutes":        quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/CreatePool":        quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/GetPool":           quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/UpdatePool":        quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/DeletePool":        quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/ListPools":         quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/GetProxyConfig":    quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/GetProxyStatus":    quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/ReloadProxyConfig": quicwire.OpGatewayCategory,
	"/platform.v1.ProxyService/GetZoneMatrix":     quicwire.OpGatewayCategory,

	// Gateway perf verification — multiplexed under OpGatewayCategory
	// (0x2F), sub-opcodes 0x36-0x38 (see categorySubOpcodeMap).
	"/platform.v1.GatewayService/GetPerfFlows":     quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/GetPerfDatapath":  quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/GetPerfConntrack": quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/GetNAT64Status":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/GetGatewayStatus": quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/SetGatewayMode":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ListIPAMPools":    quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/GetIPAMPool":      quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/CreateIPAMPool":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/UpdateIPAMPool":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/DeleteIPAMPool":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/AllocateIP":       quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ReleaseIP":        quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ListAllocations":  quicwire.OpGatewayCategory,

	"/platform.v1.GatewayService/GetBGPStatus":          quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ListBGPPeers":          quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/AnnouncePrefix":        quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/WithdrawPrefix":        quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ListAnnouncedPrefixes": quicwire.OpGatewayCategory,

	"/platform.v1.GatewayService/GetGatewayAdmittedVTEP":   quicwire.OpGatewayCategory,
	"/platform.v1.GatewayService/ListGatewayAdmittedVTEPs": quicwire.OpGatewayCategory,

	"/platform.v1.EABService/CreateCredential":          quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredential":             quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredentialByKeyID":      quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/ListCredentials":           quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/RevokeCredential":          quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/ValidateCredential":        quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/DeleteCredential":          quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredentialQRCode":       quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/GetEnrollmentURL":          quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/MarkCredentialUsed":        quicwire.OpProvisioningCategory,
	"/platform.v1.EABService/CleanupExpiredCredentials": quicwire.OpProvisioningCategory,

	// Compute Service — proto: pkg/api/grpc/proto/compute.proto
	"/platform.v1.ComputeService/CreateContainer":  quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/DeleteContainer":  quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/StartContainer":   quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/StopContainer":    quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/ListContainers":   quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/GetContainer":     quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/GetContainerLogs": quicwire.OpContainerLogs,
	"/platform.v1.ComputeService/GetVMMetrics":     quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/AttachDisk":       quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/DetachDisk":       quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/ResizeDisk":       quicwire.OpVMExtendedCategory,
	"/platform.v1.ComputeService/MigrateVM":        quicwire.OpVMExtendedCategory,

	// Switch Service — proto: pkg/api/grpc/proto/switch.proto
	// All SwitchService methods route to OpSwitchCategory (0xCC); the
	// SDK adapter prepends the sub-opcode automatically. See
	// categorySubOpcodeMap and pkg/api/daemon/quic_switch.go.
	"/platform.v1.SwitchService/ListPorts":     quicwire.OpSwitchCategory,
	"/platform.v1.SwitchService/GetPortStatus": quicwire.OpSwitchCategory,
	"/platform.v1.SwitchService/SetPortVLAN":   quicwire.OpSwitchCategory,
	"/platform.v1.SwitchService/EnablePort":    quicwire.OpSwitchCategory,
	"/platform.v1.SwitchService/DisablePort":   quicwire.OpSwitchCategory,

	// Ceremony Service — proto: pkg/api/grpc/proto/ceremony.proto
	// All CeremonyService methods route to OpCeremonyCategory (0x9A).
	// Requests and responses are translated to the daemon wire structs in
	// ceremony.go.
	"/platform.v1.CeremonyService/Init":               quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/Status":             quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/ClaimCertBegin":     quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/ClaimCertComplete":  quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/ClaimShareBegin":    quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/ClaimShareComplete": quicwire.OpCeremonyCategory,
	"/platform.v1.CeremonyService/SignCSR":            quicwire.OpCeremonyCategory,

	// PIV Service — proto: pkg/api/grpc/proto/piv.proto
	// All PIVService methods route to OpPIVCategory (0x9B). Translated in
	// piv.go.
	"/platform.v1.PIVService/ListDevices": quicwire.OpPIVCategory,
	"/platform.v1.PIVService/ListSlots":   quicwire.OpPIVCategory,
	"/platform.v1.PIVService/SlotInfo":    quicwire.OpPIVCategory,
	"/platform.v1.PIVService/Generate":    quicwire.OpPIVCategory,
	"/platform.v1.PIVService/Import":      quicwire.OpPIVCategory,
	"/platform.v1.PIVService/Sign":        quicwire.OpPIVCategory,
	"/platform.v1.PIVService/Attest":      quicwire.OpPIVCategory,
	"/platform.v1.PIVService/Reset":       quicwire.OpPIVCategory,

	// LUKS Service — proto: pkg/api/grpc/proto/luks.proto
	// All LUKSService methods route to OpLUKSCategory (0x9C). Translated in
	// luks.go.
	"/platform.v1.LUKSService/Status":           quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/ListSlots":        quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/Info":             quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/EnrollPassphrase": quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/EnrollFIDO2":      quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/EnrollTPM":        quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/EnrollRecovery":   quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/RemoveKey":        quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/TestUnlock":       quicwire.OpLUKSCategory,
	"/platform.v1.LUKSService/ChangePassphrase": quicwire.OpLUKSCategory,

	// FIDO2 Service — proto: pkg/api/grpc/proto/fido2.proto
	// All FIDO2Service methods route to OpFIDO2Category (0x9D). Translated
	// in fido2.go.
	"/platform.v1.FIDO2Service/ListDevices":  quicwire.OpFIDO2Category,
	"/platform.v1.FIDO2Service/WaitDevice":   quicwire.OpFIDO2Category,
	"/platform.v1.FIDO2Service/Info":         quicwire.OpFIDO2Category,
	"/platform.v1.FIDO2Service/Register":     quicwire.OpFIDO2Category,
	"/platform.v1.FIDO2Service/Authenticate": quicwire.OpFIDO2Category,

	// Daemon Service — proto: pkg/api/grpc/proto/daemon.proto
	"/platform.v1.PlatformDaemon/GetVersion":       quicwire.OpDaemonVersion,
	"/platform.v1.PlatformDaemon/GetStatus":        quicwire.OpDaemonStatus,
	"/platform.v1.PlatformDaemon/GetHealth":        quicwire.OpHealth,
	"/platform.v1.PlatformDaemon/Liveness":         quicwire.OpLiveness,
	"/platform.v1.PlatformDaemon/Readiness":        quicwire.OpReadiness,
	"/platform.v1.PlatformDaemon/ListServices":     quicwire.OpDaemonListServices,
	"/platform.v1.PlatformDaemon/GetServiceStatus": quicwire.OpDaemonGetService,
	"/platform.v1.PlatformDaemon/StartService":     quicwire.OpDaemonStartService,
	"/platform.v1.PlatformDaemon/StopService":      quicwire.OpDaemonStopService,
	"/platform.v1.PlatformDaemon/RestartService":   quicwire.OpDaemonRestartService,
}

// NewStream serves a server-streaming method by long-polling its unary
// twin; a method without one is Unimplemented.
func (c *quicClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return pollstream.NewStream(ctx, c, method, c.adapter.timeout, opts...)
}

// quicStatusToGRPCMap provides O(1) lookup for QUIC status to gRPC code mapping.
var quicStatusToGRPCMap = map[byte]codes.Code{
	quicwire.StatusOK:                 codes.OK,
	quicwire.StatusInvalidRequest:     codes.InvalidArgument,
	quicwire.StatusNotFound:           codes.NotFound,
	quicwire.StatusUnauthorized:       codes.Unauthenticated,
	quicwire.StatusInternalError:      codes.Internal,
	quicwire.StatusTimeout:            codes.DeadlineExceeded,
	quicwire.StatusAlreadyExists:      codes.AlreadyExists,
	quicwire.StatusPermissionDenied:   codes.PermissionDenied,
	quicwire.StatusResourceExhausted:  codes.ResourceExhausted,
	quicwire.StatusInvalidArgument:    codes.InvalidArgument,
	quicwire.StatusUnavailable:        codes.Unavailable,
	quicwire.StatusNotImplemented:     codes.Unimplemented,
	quicwire.StatusFailedPrecondition: codes.FailedPrecondition,
}

// translateQUICErrorToGRPC translates QUIC errors to gRPC status errors.
func translateQUICErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	// Check for QUIC protocol errors
	if protoErr, ok := err.(*quicwire.ErrProtocol); ok {
		code, found := quicStatusToGRPCMap[protoErr.Status]
		if !found {
			code = codes.Unknown
		}
		return status.Error(code, protoErr.Message)
	}

	// Check for client closed error
	if err == quicwire.ErrClientClosed {
		return status.Error(codes.Unavailable, "QUIC client closed")
	}

	// Check for stream errors
	if err == quicwire.ErrStreamFailed {
		return status.Error(codes.Unavailable, "QUIC stream failed")
	}

	// Default to unavailable for connection issues
	return status.Error(codes.Unavailable, err.Error())
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
