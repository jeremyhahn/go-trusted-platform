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

// Package quic provides a high-performance QUIC transport layer for the Trusted Platform.
// It implements a binary protocol over QUIC streams with MessagePack encoding,
// offering low-latency, multiplexed communication for platform services.
package quic

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
)

func init() {
	// Eagerly initialize the codec at package load time
	codecMu.Lock()
	defer codecMu.Unlock()
	if protocolCodec == nil {
		var err error
		protocolCodec, err = factory.New[any](defaultCodecType)
		if err != nil {
			protocolCodec, _ = factory.New[any](codec.JSON)
		}
	}
}

// Protocol constants
const (
	// ProtocolVersion identifies the protocol version
	ProtocolVersion byte = 0x01

	// Status codes
	StatusOK                byte = 0x00
	StatusInvalidRequest    byte = 0x01
	StatusNotFound          byte = 0x02
	StatusUnauthorized      byte = 0x03
	StatusInternalError     byte = 0x04
	StatusTimeout           byte = 0x05
	StatusAlreadyExists     byte = 0x06
	StatusPermissionDenied  byte = 0x07
	StatusResourceExhausted byte = 0x08
	StatusInvalidArgument   byte = 0x09
	StatusUnavailable       byte = 0x0A
	StatusNotImplemented    byte = 0x0B

	// MaxPayloadSize limits payload to 16MB
	MaxPayloadSize uint32 = 16 * 1024 * 1024

	// MaxTokenSize limits auth tokens to 8KB
	MaxTokenSize uint16 = 8 * 1024
)

// Platform-specific operation codes
const (
	// Health Operations (0x00-0x02)
	OpHealth    byte = 0x00
	OpLiveness  byte = 0x01
	OpReadiness byte = 0x02

	// vTPM Extended Operations (0x03-0x0F) - Template and Bundle Management
	OpVTPMCreateTemplate byte = 0x03
	OpVTPMGetTemplate    byte = 0x04
	OpVTPMDeleteTemplate byte = 0x05
	OpVTPMListTemplates  byte = 0x06
	OpVTPMCloneTemplate  byte = 0x07
	OpVTPMExportBundle   byte = 0x08
	OpVTPMImportBundle   byte = 0x09
	OpVTPMValidateBundle byte = 0x0A
	OpVTPMGetBundlePath  byte = 0x0B
	OpVTPMGetSocketPath  byte = 0x0C
	OpVTPMGetNVRAMPath   byte = 0x0D
	OpVTPMGetBundle      byte = 0x0E
	OpVTPMIsRunning      byte = 0x0F

	// vTPM Operations (0x10-0x1F)
	OpVTPMCreate      byte = 0x10
	OpVTPMDelete      byte = 0x11
	OpVTPMStart       byte = 0x12
	OpVTPMStop        byte = 0x13
	OpVTPMGetState    byte = 0x14
	OpVTPMList        byte = 0x15
	OpVTPMGetEK       byte = 0x16
	OpVTPMGetAK       byte = 0x17
	OpVTPMCreateAK    byte = 0x18
	OpVTPMQuote       byte = 0x19
	OpVTPMVerifyQuote byte = 0x1A
	OpVTPMExtendPCR   byte = 0x1B
	OpVTPMReadPCR     byte = 0x1C
	OpVTPMSeal        byte = 0x1D
	OpVTPMUnseal      byte = 0x1E
	OpVTPMGetRandom   byte = 0x1F

	// DNS Operations (0x20-0x2F)
	OpDNSAddRecord    byte = 0x20
	OpDNSDeleteRecord byte = 0x21
	OpDNSUpdateRecord byte = 0x22
	OpDNSGetRecord    byte = 0x23
	OpDNSListRecords  byte = 0x24
	OpDNSAddZone      byte = 0x25
	OpDNSDeleteZone   byte = 0x26
	OpDNSGetZone      byte = 0x27
	OpDNSListZones    byte = 0x28
	OpDNSResolve      byte = 0x29
	OpDNSGetConfig    byte = 0x2A
	OpDNSUpdateConfig byte = 0x2B
	OpDNSGetMetrics   byte = 0x2C
	OpDNSFlushCache   byte = 0x2D

	// SDN Overlay/Gateway/IPAM Category Opcodes (0x2E-0x2F)
	// These are "category" opcodes that multiplex multiple sub-operations.
	// The first byte of the payload is the sub-opcode routed to the category handler.
	OpOverlayCategory byte = 0x2E
	OpGatewayCategory byte = 0x2F

	// Device Operations (0x30-0x3F)
	OpDeviceRegister      byte = 0x30
	OpDeviceUnregister    byte = 0x31
	OpDeviceGet           byte = 0x32
	OpDeviceList          byte = 0x33
	OpDeviceUpdate        byte = 0x34
	OpDeviceGetProfile    byte = 0x35
	OpDeviceSetProfile    byte = 0x36
	OpDeviceListProfiles  byte = 0x37
	OpDeviceCreateProfile byte = 0x38
	OpDeviceDeleteProfile byte = 0x39
	OpDeviceAttest        byte = 0x3A
	OpDeviceActivate      byte = 0x3B
	OpDeviceDeactivate    byte = 0x3C
	OpDeviceGetState      byte = 0x3D
	OpDeviceGetMetrics    byte = 0x3E

	// SDN IPAM Category Opcode (0x3F)
	// Category opcode that multiplexes IPAM sub-operations.
	// The first byte of the payload is the sub-opcode routed to the gateway handler.
	OpIPAMCategory byte = 0x3F

	// SDN/Network Operations (0x40-0x4F)
	OpSDNGetPortState byte = 0x40
	OpSDNSetPortState byte = 0x41
	OpSDNListPorts    byte = 0x42
	OpSDNGetFlow      byte = 0x43
	OpSDNAddFlow      byte = 0x44
	OpSDNDeleteFlow   byte = 0x45
	OpSDNListFlows    byte = 0x46
	OpSDNApplyPolicy  byte = 0x47
	OpSDNGetPolicy    byte = 0x48
	OpSDNListPolicies byte = 0x49
	OpSDNGetBridge    byte = 0x4A
	OpSDNListBridges  byte = 0x4B
	OpSDNGetMetrics   byte = 0x4C
	OpSDNSetVLAN      byte = 0x4D
	OpSDNGetVLAN      byte = 0x4E
	OpSDNGetPort      byte = 0x4F

	// NTP (time synchronization) Category Opcode (0x50)
	//
	// The 0x50-0x55 block originally held direct OpProv* provisioning
	// opcodes that were never implemented or dispatched — the real
	// provisioning surface ships under OpProvisioningCategory (0xCF). The
	// head of that dead range is reclaimed for the time-synchronization
	// category (see ntp_opcodes.go); 0x51-0x55 stay reserved for NTP
	// growth.

	// IDevID/IAK Device Identity Operations (0x56-0x5F)
	OpIDevIDGenerate    byte = 0x56
	OpIDevIDInfo        byte = 0x57
	OpIDevIDDelete      byte = 0x58
	OpIDevIDCSR         byte = 0x59
	OpIDevIDInstallCert byte = 0x5A
	OpIDevIDGetCert     byte = 0x5B
	OpIAKGenerate       byte = 0x5C
	OpIAKInfo           byte = 0x5D
	OpIAKDelete         byte = 0x5E
	OpIAKCSR            byte = 0x5F

	// Compute/VM Operations (0x60-0x6F)
	OpVMCreate    byte = 0x60
	OpVMDelete    byte = 0x61
	OpVMStart     byte = 0x62
	OpVMStop      byte = 0x63
	OpVMGet       byte = 0x64
	OpVMList      byte = 0x65
	OpVMAttachNet byte = 0x66
	OpVMDetachNet byte = 0x67
	OpVMActivate  byte = 0x68
	// OpVMExtendedCategory multiplexes the extended VM operations
	// (restart, suspend, resume, attest, attest-verify, console, and
	// snapshot create/restore/delete/list) as sub-opcodes carried in
	// payload[0]. The direct opcodes 0xB6-0xBE collide with the IAM
	// role/group ranges at the top level, so transports reach the
	// extended VM surface through this category opcode inside the VM
	// range (it replaces the never-implemented OpVMDeactivate
	// allocation).
	OpVMExtendedCategory byte = 0x69
	OpVMGetState         byte = 0x6A

	// IAK Extended Operations (0x6B-0x6F)
	OpIAKInstallCert     byte = 0x6B
	OpIAKGetCert         byte = 0x6C
	OpDeviceAttributes   byte = 0x6D
	OpActivateCredential byte = 0x6E
	// 0x6F reserved

	// Attestation Operations (0x70-0x7F)
	OpAttestQuote       byte = 0x70
	OpAttestVerify      byte = 0x71
	OpAttestCollectHost byte = 0x72 // repurposed from the never-implemented OpAttestGetEK
	OpAttestGetAK       byte = 0x73
	OpAttestChallenge   byte = 0x74
	OpAttestResponse    byte = 0x75
	OpAttestGetReport   byte = 0x76
	OpAttestGetPCRs     byte = 0x77
	// 0x78-0x7E reserved
	// IDevID/IAK Extended Operations (0x7F)
	OpHasIDevID        byte = 0x78
	OpHasIAK           byte = 0x79
	OpIDevIDDeleteCert byte = 0x7A
	OpIAKDeleteCert    byte = 0x7B

	// Certificate/PKI Operations (0x80-0x88)
	OpCertIssue    byte = 0x80
	OpCertRevoke   byte = 0x81
	OpCertRenew    byte = 0x82
	OpCertGet      byte = 0x83
	OpCertList     byte = 0x84
	OpCertVerify   byte = 0x85
	OpCertGetChain byte = 0x86
	OpCertGetCRL   byte = 0x87
	OpCertGetOCSP  byte = 0x88

	// Daemon Management Operations (0x89-0x8F, 0x98)
	// Uses the gap between Certificate/PKI and JWT/Auth operation ranges.
	OpDaemonStatus         byte = 0x89
	OpDaemonVersion        byte = 0x8A
	OpDaemonListServices   byte = 0x8B
	OpDaemonGetService     byte = 0x8C
	OpDaemonStartService   byte = 0x8D
	OpDaemonStopService    byte = 0x8E
	OpDaemonRestartService byte = 0x8F
	OpDaemonListProtocols  byte = 0x98

	// TPM2 Category Opcode (0x99)
	// Category opcode that multiplexes physical TPM2 sub-operations.
	// The first byte of the payload is the sub-opcode routed to the TPM2 handler.
	OpTPM2Category byte = 0x99

	// JWT/Auth Operations (0x90-0x97)
	OpJWTCreate  byte = 0x90
	OpJWTVerify  byte = 0x91
	OpJWTRefresh byte = 0x92
	OpJWTRevoke  byte = 0x93
	OpJWTGetKeys byte = 0x94
	OpAuthLogin  byte = 0x95
	OpAuthLogout byte = 0x96
	OpAuthCheck  byte = 0x97

	// CA Operations (0xA0-0xA8)
	OpCAInfo   byte = 0xA0
	OpCAIssue  byte = 0xA1
	OpCARevoke byte = 0xA2
	OpCARenew  byte = 0xA3
	OpCAGet    byte = 0xA4
	OpCAList   byte = 0xA5
	OpCAVerify byte = 0xA6
	OpCACRL    byte = 0xA7
	OpCABundle byte = 0xA8

	// IAM User Operations (0xA9-0xAD)
	OpIAMUserCreate byte = 0xA9
	OpIAMUserDelete byte = 0xAA
	OpIAMUserGet    byte = 0xAB
	OpIAMUserList   byte = 0xAC
	OpIAMUserUpdate byte = 0xAD

	// SDN Extended Operations (0xB0-0xB4)
	OpSDNCreateBridge byte = 0xB0
	OpSDNDeleteBridge byte = 0xB1
	OpSDNCreatePort   byte = 0xB2
	OpSDNDeletePort   byte = 0xB3
	OpSDNDeletePolicy byte = 0xB4

	// IAM Role Operations (0xB5-0xBA)
	OpIAMRoleCreate byte = 0xB5
	OpIAMRoleDelete byte = 0xB6
	OpIAMRoleGet    byte = 0xB7
	OpIAMRoleList   byte = 0xB8
	OpIAMRoleAssign byte = 0xB9
	OpIAMRoleRevoke byte = 0xBA

	// IAM Group Operations (0xBB-0xBF)
	OpIAMGroupCreate    byte = 0xBB
	OpIAMGroupDelete    byte = 0xBC
	OpIAMGroupGet       byte = 0xBD
	OpIAMGroupList      byte = 0xBE
	OpIAMGroupAddMember byte = 0xBF

	// KMS Key Management Operations (0xC0-0xCF)
	OpKMSGenerateKey     byte = 0xC0
	OpKMSImportKey       byte = 0xC1
	OpKMSGetKey          byte = 0xC2
	OpKMSListKeys        byte = 0xC3
	OpKMSDeleteKey       byte = 0xC4
	OpKMSRotateKey       byte = 0xC5
	OpKMSUpdateKeyStatus byte = 0xC6
	OpKMSExportKey       byte = 0xC7
	OpKMSGetKeyVersions  byte = 0xC8
	OpKMSBackendStatus   byte = 0xC9
	OpKMSBatchEncrypt    byte = 0xCA // Batch encrypt multiple items
	OpKMSBatchDecrypt    byte = 0xCB // Batch decrypt multiple items
	// Switch Management Category Opcode (0xCC)
	// Uses category pattern: first payload byte is sub-opcode.
	OpSwitchCategory byte = 0xCC

	// 0xCD is OpKMSExtendedCategory, 0xCE is OpSecretsCategory, and
	// 0xCF is OpProvisioningCategory (see kms_opcodes.go and
	// provisioning_opcodes.go). The 0xC0-0xCF range is now fully
	// allocated — as is the ENTIRE single-byte opcode space (0x00-0xFF,
	// counting the container/attestation extensions in
	// container_handlers.go and attestation_handlers.go). New services
	// must multiplex as sub-opcodes under an existing category opcode;
	// EAB credential management does so under OpProvisioningCategory
	// (sub-range 0x10-0x1A, see eab_opcodes.go).

	// KMS Crypto Operations (0xD0-0xDA)
	OpKMSEncrypt                byte = 0xD0
	OpKMSDecrypt                byte = 0xD1
	OpKMSSign                   byte = 0xD2
	OpKMSVerify                 byte = 0xD3
	OpKMSGenerateRandom         byte = 0xD4
	OpKMSHash                   byte = 0xD5
	OpKMSHMAC                   byte = 0xD6
	OpKMSVerifyHMAC             byte = 0xD7
	OpKMSRewrap                 byte = 0xD8
	OpKMSGenerateDataKey        byte = 0xD9
	OpKMSGenerateWrappedDataKey byte = 0xDA

	// DEK Management Operations (0xF0-0xF5)
	OpDEKCreate    byte = 0xF0
	OpDEKGet       byte = 0xF1
	OpDEKList      byte = 0xF2
	OpDEKDelete    byte = 0xF3
	OpDEKRotate    byte = 0xF4
	OpDEKGetStatus byte = 0xF5

	// IAM Extended Operations (0xF6-0xFB)
	OpIAMGroupRemoveMember byte = 0xF6
	OpIAMCheckPermission   byte = 0xF7
	OpIAMAuthenticate      byte = 0xF8
	OpIAMTokenCreate       byte = 0xF9
	OpIAMTokenRevoke       byte = 0xFA
	OpIAMTokenVerify       byte = 0xFB

	// PXE Extended Operations (0xFC-0xFF)
	OpPXEAuthorize    byte = 0xFC
	OpPXEQuarantine   byte = 0xFD
	OpPXERetry        byte = 0xFE
	OpPXERemoveDevice byte = 0xFF
)

// PXE Provisioning Operations (single-byte, legacy range)
const (
	OpPXEListDevices    byte = 0xEC
	OpPXEGetDevice      byte = 0xED
	OpPXERegisterDevice byte = 0xEE
	OpPXEUpdateState    byte = 0xEF
)

// Tenant Extended Opcodes (using extended opcode space via two-byte opcodes)
// These use the high byte 0x02 to indicate tenant operations
// Tenant Management Operations (0xDB-0xEB range)
// Relocated from 0x10-0x1E to avoid conflict with vTPM opcodes (0x10-0x1F)
const (
	OpTenantList         byte = 0xDB // List all tenants with pagination
	OpTenantGet          byte = 0xDC // Get tenant by ID
	OpTenantGetByName    byte = 0xDD // Get tenant by name
	OpTenantCreate       byte = 0xDE // Create new tenant
	OpTenantUpdate       byte = 0xDF // Update tenant metadata
	OpTenantDelete       byte = 0xE0 // Delete tenant
	OpTenantSuspend      byte = 0xE1 // Suspend tenant
	OpTenantResume       byte = 0xE2 // Resume tenant
	OpTenantGetQuotas    byte = 0xE3 // Get tenant quotas
	OpTenantUpdateQuotas byte = 0xE4 // Update tenant quotas
	OpTenantGetUsage     byte = 0xE5 // Get usage stats
	OpTenantCheckQuota   byte = 0xE6 // Check quota availability
	// 0xE7 and 0xE8 (ValidateVLAN, GetBridge) were retired with the
	// per-tenant VLAN range and OVS bridge (#708); do not reuse them.
	OpTenantSync         byte = 0xE9 // Synchronize tenant state
	OpTenantRotateDEK    byte = 0xEA // Rotate tenant DEK
	OpTenantGetDEKStatus byte = 0xEB // Get tenant DEK status
)

// Request represents a QUIC protocol request
// Wire format: [opcode:1][tokenLen:2][token:N][payloadLen:4][payload:M]
type Request struct {
	Opcode  byte
	Token   string // Authentication token (JWT or similar)
	Payload []byte
}

// Response represents a QUIC protocol response
// Wire format: [status:1][payloadLen:4][payload:N]
type Response struct {
	Status  byte
	Payload []byte
}

// WriteRequest writes a request to the stream
func WriteRequest(w io.Writer, req *Request) error {
	if req == nil {
		return &MessageError{Msg: "request cannot be nil"}
	}

	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxPayloadSize {
		return &MessageError{Msg: fmt.Sprintf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)}
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxTokenSize {
		return &MessageError{Msg: fmt.Sprintf("token size %d exceeds maximum %d", tokenLen, MaxTokenSize)}
	}

	// Write opcode
	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return &WrappedError{Msg: "failed to write opcode", Err: err}
	}

	// Write token length (big-endian, 2 bytes)
	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return &WrappedError{Msg: "failed to write token length", Err: err}
	}

	// Write token
	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return &WrappedError{Msg: "failed to write token", Err: err}
		}
	}

	// Write payload length (big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return &WrappedError{Msg: "failed to write payload length", Err: err}
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return &WrappedError{Msg: "failed to write payload", Err: err}
		}
	}

	return nil
}

// ReadRequest reads a request from the stream
func ReadRequest(r io.Reader) (*Request, error) {
	// Read opcode
	opcodeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, opcodeBuf); err != nil {
		return nil, &WrappedError{Msg: "failed to read opcode", Err: err}
	}

	// Read token length
	tokenLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, tokenLenBuf); err != nil {
		return nil, &WrappedError{Msg: "failed to read token length", Err: err}
	}
	tokenLen := binary.BigEndian.Uint16(tokenLenBuf)

	if tokenLen > MaxTokenSize {
		return nil, &MessageError{Msg: fmt.Sprintf("token size %d exceeds maximum %d", tokenLen, MaxTokenSize)}
	}

	// Read token
	var token string
	if tokenLen > 0 {
		tokenBuf := make([]byte, tokenLen)
		if _, err := io.ReadFull(r, tokenBuf); err != nil {
			return nil, &WrappedError{Msg: "failed to read token", Err: err}
		}
		token = string(tokenBuf)
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, &WrappedError{Msg: "failed to read payload length", Err: err}
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxPayloadSize {
		return nil, &MessageError{Msg: fmt.Sprintf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)}
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, &WrappedError{Msg: "failed to read payload", Err: err}
		}
	}

	return &Request{
		Opcode:  opcodeBuf[0],
		Token:   token,
		Payload: payload,
	}, nil
}

// WriteResponse writes a response to the stream.
//
// The entire frame [status:1][payloadLen:4][payload:N] is assembled into a
// single buffer and written with one Write call. This is critical for QUIC
// streams: quic-go may flush each Write as a separate STREAM frame, and when
// stream.Close() follows immediately (as in handleStream's defer), the FIN can
// race with a pending multi-write sequence, causing the client to receive the
// 5-byte header (status + length) but get EOF before the payload bytes arrive.
// A single atomic Write eliminates that race entirely.
func WriteResponse(w io.Writer, resp *Response) error {
	if resp == nil {
		return &MessageError{Msg: "response cannot be nil"}
	}

	payloadLen := uint32(len(resp.Payload))
	if payloadLen > MaxPayloadSize {
		return &MessageError{Msg: fmt.Sprintf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)}
	}

	// Assemble [status:1][len:4][payload:N] into a single buffer so the
	// entire response is dispatched in one Write call.
	frame := make([]byte, 5+payloadLen)
	frame[0] = resp.Status
	binary.BigEndian.PutUint32(frame[1:5], payloadLen)
	if payloadLen > 0 {
		copy(frame[5:], resp.Payload)
	}

	if _, err := w.Write(frame); err != nil {
		return &WrappedError{Msg: "failed to write response", Err: err}
	}

	return nil
}

// ReadResponse reads a response from the stream
func ReadResponse(r io.Reader) (*Response, error) {
	// Read status
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, &WrappedError{Msg: "failed to read status", Err: err}
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, &WrappedError{Msg: "failed to read payload length", Err: err}
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxPayloadSize {
		return nil, &MessageError{Msg: fmt.Sprintf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)}
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, &WrappedError{Msg: "failed to read payload", Err: err}
		}
	}

	return &Response{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

var (
	// defaultCodecType is the default codec type for payload encoding/decoding
	defaultCodecType = codec.MsgPack

	// protocolCodec is the singleton codec for payload encoding/decoding
	protocolCodec codec.Codec[any]

	// codecMu protects codec type changes
	codecMu sync.RWMutex
)

// SetDefaultCodecType sets the default codec type for payload encoding/decoding.
// This must be called before any encoding/decoding operations.
// Returns an error if the codec type is not supported.
func SetDefaultCodecType(codecType codec.Type) error {
	if !codec.IsSupported(codecType) {
		return codec.ErrCodecNotSupported{CodecType: codecType}
	}
	codecMu.Lock()
	defer codecMu.Unlock()
	defaultCodecType = codecType
	// Create new codec immediately
	var err error
	protocolCodec, err = factory.New[any](codecType)
	if err != nil {
		protocolCodec, _ = factory.New[any](codec.JSON)
	}
	return nil
}

// GetDefaultCodecType returns the current default codec type.
func GetDefaultCodecType() codec.Type {
	codecMu.RLock()
	defer codecMu.RUnlock()
	return defaultCodecType
}

// SupportedCodecs returns a list of all codecs available in this build.
func SupportedCodecs() []codec.Type {
	return codec.SupportedCodecs()
}

// IsCodecSupported returns true if the given codec type is available.
func IsCodecSupported(codecType codec.Type) bool {
	return codec.IsSupported(codecType)
}

// getCodec returns the protocol codec, initializing it if necessary.
func getCodec() codec.Codec[any] {
	codecMu.RLock()
	c := protocolCodec
	codecMu.RUnlock()

	if c != nil {
		return c
	}

	// Initialize codec on first use
	codecMu.Lock()
	defer codecMu.Unlock()

	// Double-check after acquiring write lock
	if protocolCodec != nil {
		return protocolCodec
	}

	var err error
	protocolCodec, err = factory.New[any](defaultCodecType)
	if err != nil {
		// Fallback to JSON if the configured codec fails (e.g., MsgPack not available)
		protocolCodec, _ = factory.New[any](codec.JSON)
	}
	return protocolCodec
}

// EncodePayload encodes an entity using the configured codec
func EncodePayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c := getCodec()
	if c == nil {
		return nil, &MessageError{Msg: "no codec available for encoding"}
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to encode payload", Err: err}
	}

	return data, nil
}

// DecodePayload decodes bytes into an entity using the configured codec
func DecodePayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return &MessageError{Msg: "entity cannot be nil"}
	}

	c := getCodec()
	if c == nil {
		return &MessageError{Msg: "no codec available for decoding"}
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return &WrappedError{Msg: "failed to decode payload", Err: err}
	}

	return nil
}

// EncodePayloadWithCodec encodes an entity using a specific codec type
func EncodePayloadWithCodec(entity interface{}, codecType codec.Type) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := factory.New[any](codecType)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create codec", Err: err}
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to encode payload", Err: err}
	}

	return data, nil
}

// DecodePayloadWithCodec decodes bytes into an entity using a specific codec type
func DecodePayloadWithCodec(data []byte, entity interface{}, codecType codec.Type) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return &MessageError{Msg: "entity cannot be nil"}
	}

	c, err := factory.New[any](codecType)
	if err != nil {
		return &WrappedError{Msg: "failed to create codec", Err: err}
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return &WrappedError{Msg: "failed to decode payload", Err: err}
	}

	return nil
}

// opcodeNames maps each platform operation code to its human-readable name.
var opcodeNames = map[byte]string{
	// Health
	OpHealth:    "Health",
	OpLiveness:  "Liveness",
	OpReadiness: "Readiness",

	// vTPM Extended Operations
	OpVTPMCreateTemplate: "VTPMCreateTemplate",
	OpVTPMGetTemplate:    "VTPMGetTemplate",
	OpVTPMDeleteTemplate: "VTPMDeleteTemplate",
	OpVTPMListTemplates:  "VTPMListTemplates",
	OpVTPMCloneTemplate:  "VTPMCloneTemplate",
	OpVTPMExportBundle:   "VTPMExportBundle",
	OpVTPMImportBundle:   "VTPMImportBundle",
	OpVTPMValidateBundle: "VTPMValidateBundle",
	OpVTPMGetBundlePath:  "VTPMGetBundlePath",
	OpVTPMGetSocketPath:  "VTPMGetSocketPath",
	OpVTPMGetNVRAMPath:   "VTPMGetNVRAMPath",
	OpVTPMGetBundle:      "VTPMGetBundle",
	OpVTPMIsRunning:      "VTPMIsRunning",

	// vTPM
	OpVTPMCreate:      "VTPMCreate",
	OpVTPMDelete:      "VTPMDelete",
	OpVTPMStart:       "VTPMStart",
	OpVTPMStop:        "VTPMStop",
	OpVTPMGetState:    "VTPMGetState",
	OpVTPMList:        "VTPMList",
	OpVTPMGetEK:       "VTPMGetEK",
	OpVTPMGetAK:       "VTPMGetAK",
	OpVTPMCreateAK:    "VTPMCreateAK",
	OpVTPMQuote:       "VTPMQuote",
	OpVTPMVerifyQuote: "VTPMVerifyQuote",
	OpVTPMExtendPCR:   "VTPMExtendPCR",
	OpVTPMReadPCR:     "VTPMReadPCR",
	OpVTPMSeal:        "VTPMSeal",
	OpVTPMUnseal:      "VTPMUnseal",
	OpVTPMGetRandom:   "VTPMGetRandom",

	// DNS
	OpDNSAddRecord:    "DNSAddRecord",
	OpDNSDeleteRecord: "DNSDeleteRecord",
	OpDNSUpdateRecord: "DNSUpdateRecord",
	OpDNSGetRecord:    "DNSGetRecord",
	OpDNSListRecords:  "DNSListRecords",
	OpDNSAddZone:      "DNSAddZone",
	OpDNSDeleteZone:   "DNSDeleteZone",
	OpDNSGetZone:      "DNSGetZone",
	OpDNSListZones:    "DNSListZones",
	OpDNSResolve:      "DNSResolve",
	OpDNSGetConfig:    "DNSGetConfig",
	OpDNSUpdateConfig: "DNSUpdateConfig",
	OpDNSGetMetrics:   "DNSGetMetrics",
	OpDNSFlushCache:   "DNSFlushCache",
	OpOverlayCategory: "OverlayCategory",
	OpGatewayCategory: "GatewayCategory",

	// Device
	OpDeviceRegister:      "DeviceRegister",
	OpDeviceUnregister:    "DeviceUnregister",
	OpDeviceGet:           "DeviceGet",
	OpDeviceList:          "DeviceList",
	OpDeviceUpdate:        "DeviceUpdate",
	OpDeviceGetProfile:    "DeviceGetProfile",
	OpDeviceSetProfile:    "DeviceSetProfile",
	OpDeviceListProfiles:  "DeviceListProfiles",
	OpDeviceCreateProfile: "DeviceCreateProfile",
	OpDeviceDeleteProfile: "DeviceDeleteProfile",
	OpDeviceAttest:        "DeviceAttest",
	OpDeviceActivate:      "DeviceActivate",
	OpDeviceDeactivate:    "DeviceDeactivate",
	OpDeviceGetState:      "DeviceGetState",
	OpDeviceGetMetrics:    "DeviceGetMetrics",
	OpIPAMCategory:        "IPAMCategory",

	// SDN
	OpSDNGetPortState: "SDNGetPortState",
	OpSDNSetPortState: "SDNSetPortState",
	OpSDNListPorts:    "SDNListPorts",
	OpSDNGetFlow:      "SDNGetFlow",
	OpSDNAddFlow:      "SDNAddFlow",
	OpSDNDeleteFlow:   "SDNDeleteFlow",
	OpSDNListFlows:    "SDNListFlows",
	OpSDNApplyPolicy:  "SDNApplyPolicy",
	OpSDNGetPolicy:    "SDNGetPolicy",
	OpSDNListPolicies: "SDNListPolicies",
	OpSDNGetBridge:    "SDNGetBridge",
	OpSDNListBridges:  "SDNListBridges",
	OpSDNGetMetrics:   "SDNGetMetrics",
	OpSDNSetVLAN:      "SDNSetVLAN",
	OpSDNGetVLAN:      "SDNGetVLAN",
	OpSDNGetPort:      "SDNGetPort",
	OpSDNCreateBridge: "SDNCreateBridge",
	OpSDNDeleteBridge: "SDNDeleteBridge",
	OpSDNCreatePort:   "SDNCreatePort",
	OpSDNDeletePort:   "SDNDeletePort",
	OpSDNDeletePolicy: "SDNDeletePolicy",

	// NTP (time synchronization)
	OpNTPCategory: "NTPCategory",

	// IDevID/IAK Device Identity
	OpIDevIDGenerate:     "IDevIDGenerate",
	OpIDevIDInfo:         "IDevIDInfo",
	OpIDevIDDelete:       "IDevIDDelete",
	OpIDevIDCSR:          "IDevIDCSR",
	OpIDevIDInstallCert:  "IDevIDInstallCert",
	OpIDevIDGetCert:      "IDevIDGetCert",
	OpIAKGenerate:        "IAKGenerate",
	OpIAKInfo:            "IAKInfo",
	OpIAKDelete:          "IAKDelete",
	OpIAKCSR:             "IAKCSR",
	OpIAKInstallCert:     "IAKInstallCert",
	OpIAKGetCert:         "IAKGetCert",
	OpDeviceAttributes:   "DeviceAttributes",
	OpActivateCredential: "ActivateCredential",
	OpHasIDevID:          "HasIDevID",
	OpHasIAK:             "HasIAK",
	OpIDevIDDeleteCert:   "IDevIDDeleteCert",
	OpIAKDeleteCert:      "IAKDeleteCert",

	// VM
	OpVMCreate:           "VMCreate",
	OpVMDelete:           "VMDelete",
	OpVMStart:            "VMStart",
	OpVMStop:             "VMStop",
	OpVMGet:              "VMGet",
	OpVMList:             "VMList",
	OpVMAttachNet:        "VMAttachNet",
	OpVMDetachNet:        "VMDetachNet",
	OpVMActivate:         "VMActivate",
	OpVMExtendedCategory: "VMExtendedCategory",
	OpVMGetState:         "VMGetState",

	// Attestation
	OpAttestQuote:       "AttestQuote",
	OpAttestVerify:      "AttestVerify",
	OpAttestCollectHost: "AttestCollectHost",
	OpAttestGetAK:       "AttestGetAK",
	OpAttestChallenge:   "AttestChallenge",
	OpAttestResponse:    "AttestResponse",
	OpAttestGetReport:   "AttestGetReport",
	OpAttestGetPCRs:     "AttestGetPCRs",

	// Certificate
	OpCertIssue:    "CertIssue",
	OpCertRevoke:   "CertRevoke",
	OpCertRenew:    "CertRenew",
	OpCertGet:      "CertGet",
	OpCertList:     "CertList",
	OpCertVerify:   "CertVerify",
	OpCertGetChain: "CertGetChain",
	OpCertGetCRL:   "CertGetCRL",
	OpCertGetOCSP:  "CertGetOCSP",

	// Daemon Management
	OpDaemonStatus:         "DaemonStatus",
	OpDaemonVersion:        "DaemonVersion",
	OpDaemonListServices:   "DaemonListServices",
	OpDaemonGetService:     "DaemonGetService",
	OpDaemonStartService:   "DaemonStartService",
	OpDaemonStopService:    "DaemonStopService",
	OpDaemonRestartService: "DaemonRestartService",
	OpDaemonListProtocols:  "DaemonListProtocols",

	// TPM2 Category
	OpTPM2Category: "TPM2Category",
	// JWT/Auth
	OpJWTCreate:  "JWTCreate",
	OpJWTVerify:  "JWTVerify",
	OpJWTRefresh: "JWTRefresh",
	OpJWTRevoke:  "JWTRevoke",
	OpJWTGetKeys: "JWTGetKeys",
	OpAuthLogin:  "AuthLogin",
	OpAuthLogout: "AuthLogout",
	OpAuthCheck:  "AuthCheck",

	// CA Operations
	OpCAInfo:   "CAInfo",
	OpCAIssue:  "CAIssue",
	OpCARevoke: "CARevoke",
	OpCARenew:  "CARenew",
	OpCAGet:    "CAGet",
	OpCAList:   "CAList",
	OpCAVerify: "CAVerify",
	OpCACRL:    "CACRL",
	OpCABundle: "CABundle",

	// IAM User Operations
	OpIAMUserCreate: "IAMUserCreate",
	OpIAMUserDelete: "IAMUserDelete",
	OpIAMUserGet:    "IAMUserGet",
	OpIAMUserList:   "IAMUserList",
	OpIAMUserUpdate: "IAMUserUpdate",

	// IAM Role Operations
	OpIAMRoleCreate: "IAMRoleCreate",
	OpIAMRoleDelete: "IAMRoleDelete",
	OpIAMRoleGet:    "IAMRoleGet",
	OpIAMRoleList:   "IAMRoleList",
	OpIAMRoleAssign: "IAMRoleAssign",
	OpIAMRoleRevoke: "IAMRoleRevoke",

	// IAM Group Operations
	OpIAMGroupCreate:       "IAMGroupCreate",
	OpIAMGroupDelete:       "IAMGroupDelete",
	OpIAMGroupGet:          "IAMGroupGet",
	OpIAMGroupList:         "IAMGroupList",
	OpIAMGroupAddMember:    "IAMGroupAddMember",
	OpIAMGroupRemoveMember: "IAMGroupRemoveMember",

	// IAM Permission/Auth Operations
	OpIAMCheckPermission: "IAMCheckPermission",
	OpIAMAuthenticate:    "IAMAuthenticate",
	OpIAMTokenCreate:     "IAMTokenCreate",
	OpIAMTokenRevoke:     "IAMTokenRevoke",
	OpIAMTokenVerify:     "IAMTokenVerify",

	// KMS Key Management
	OpKMSGenerateKey:     "KMSGenerateKey",
	OpKMSImportKey:       "KMSImportKey",
	OpKMSGetKey:          "KMSGetKey",
	OpKMSListKeys:        "KMSListKeys",
	OpKMSDeleteKey:       "KMSDeleteKey",
	OpKMSRotateKey:       "KMSRotateKey",
	OpKMSUpdateKeyStatus: "KMSUpdateKeyStatus",
	OpKMSExportKey:       "KMSExportKey",
	OpKMSGetKeyVersions:  "KMSGetKeyVersions",
	OpKMSBackendStatus:   "KMSBackendStatus",
	OpKMSBatchEncrypt:    "KMSBatchEncrypt",
	OpKMSBatchDecrypt:    "KMSBatchDecrypt",
	OpSwitchCategory:     "SwitchCategory",

	// KMS Extended, Secrets, and Provisioning Categories
	OpKMSExtendedCategory:  "KMSExtendedCategory",
	OpSecretsCategory:      "SecretsCategory",
	OpProvisioningCategory: "ProvisioningCategory",

	// KMS Crypto Operations
	OpKMSEncrypt:                "KMSEncrypt",
	OpKMSDecrypt:                "KMSDecrypt",
	OpKMSSign:                   "KMSSign",
	OpKMSVerify:                 "KMSVerify",
	OpKMSGenerateRandom:         "KMSGenerateRandom",
	OpKMSHash:                   "KMSHash",
	OpKMSHMAC:                   "KMSHMAC",
	OpKMSVerifyHMAC:             "KMSVerifyHMAC",
	OpKMSRewrap:                 "KMSRewrap",
	OpKMSGenerateDataKey:        "KMSGenerateDataKey",
	OpKMSGenerateWrappedDataKey: "KMSGenerateWrappedDataKey",

	// DEK Management
	OpDEKCreate:    "DEKCreate",
	OpDEKGet:       "DEKGet",
	OpDEKList:      "DEKList",
	OpDEKDelete:    "DEKDelete",
	OpDEKRotate:    "DEKRotate",
	OpDEKGetStatus: "DEKGetStatus",

	// PXE Provisioning
	OpPXEListDevices:    "PXEListDevices",
	OpPXEGetDevice:      "PXEGetDevice",
	OpPXERegisterDevice: "PXERegisterDevice",
	OpPXEUpdateState:    "PXEUpdateState",
	OpPXEAuthorize:      "PXEAuthorize",
	OpPXEQuarantine:     "PXEQuarantine",
	OpPXERetry:          "PXERetry",
	OpPXERemoveDevice:   "PXERemoveDevice",
}

// OpcodeToString returns a human-readable name for an opcode
func OpcodeToString(opcode byte) string {
	if name, ok := opcodeNames[opcode]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", opcode)
}

// tenantOpcodeNames maps each tenant operation code to its human-readable name.
var tenantOpcodeNames = map[byte]string{
	OpTenantList:         "TenantList",
	OpTenantGet:          "TenantGet",
	OpTenantGetByName:    "TenantGetByName",
	OpTenantCreate:       "TenantCreate",
	OpTenantUpdate:       "TenantUpdate",
	OpTenantDelete:       "TenantDelete",
	OpTenantSuspend:      "TenantSuspend",
	OpTenantResume:       "TenantResume",
	OpTenantGetQuotas:    "TenantGetQuotas",
	OpTenantUpdateQuotas: "TenantUpdateQuotas",
	OpTenantGetUsage:     "TenantGetUsage",
	OpTenantCheckQuota:   "TenantCheckQuota",
	OpTenantSync:         "TenantSync",
	OpTenantRotateDEK:    "TenantRotateDEK",
	OpTenantGetDEKStatus: "TenantGetDEKStatus",
}

// TenantOpcodeToString returns a human-readable name for a tenant opcode
func TenantOpcodeToString(opcode byte) string {
	if name, ok := tenantOpcodeNames[opcode]; ok {
		return name
	}
	return fmt.Sprintf("UnknownTenantOp(0x%02X)", opcode)
}

// statusNames maps each status code to its human-readable name.
var statusNames = map[byte]string{
	StatusOK:                "OK",
	StatusInvalidRequest:    "InvalidRequest",
	StatusNotFound:          "NotFound",
	StatusUnauthorized:      "Unauthorized",
	StatusInternalError:     "InternalError",
	StatusTimeout:           "Timeout",
	StatusAlreadyExists:     "AlreadyExists",
	StatusPermissionDenied:  "PermissionDenied",
	StatusResourceExhausted: "ResourceExhausted",
	StatusInvalidArgument:   "InvalidArgument",
	StatusUnavailable:       "Unavailable",
	StatusNotImplemented:    "NotImplemented",
}

// StatusToString returns a human-readable name for a status code
func StatusToString(status byte) string {
	if name, ok := statusNames[status]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", status)
}

// IsTenantOpcode checks if an opcode belongs to the tenant operation category
func IsTenantOpcode(opcode byte) bool {
	return opcode >= OpTenantList && opcode <= OpTenantGetDEKStatus
}
