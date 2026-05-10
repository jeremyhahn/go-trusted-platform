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

	// Provisioning Operations (0x50-0x55)
	OpProvFetchProfile byte = 0x50
	OpProvActivate     byte = 0x51
	OpProvDeactivate   byte = 0x52
	OpProvGetState     byte = 0x53
	OpProvEnroll       byte = 0x54
	OpProvRenew        byte = 0x55

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
	OpVMCreate     byte = 0x60
	OpVMDelete     byte = 0x61
	OpVMStart      byte = 0x62
	OpVMStop       byte = 0x63
	OpVMGet        byte = 0x64
	OpVMList       byte = 0x65
	OpVMAttachNet  byte = 0x66
	OpVMDetachNet  byte = 0x67
	OpVMActivate   byte = 0x68
	OpVMDeactivate byte = 0x69
	OpVMGetState   byte = 0x6A

	// IAK Extended Operations (0x6B-0x6F)
	OpIAKInstallCert     byte = 0x6B
	OpIAKGetCert         byte = 0x6C
	OpDeviceAttributes   byte = 0x6D
	OpActivateCredential byte = 0x6E
	// 0x6F reserved

	// Attestation Operations (0x70-0x7F)
	OpAttestQuote     byte = 0x70
	OpAttestVerify    byte = 0x71
	OpAttestGetEK     byte = 0x72
	OpAttestGetAK     byte = 0x73
	OpAttestChallenge byte = 0x74
	OpAttestResponse  byte = 0x75
	OpAttestGetReport byte = 0x76
	OpAttestGetPCRs   byte = 0x77
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

	// 0xCD-0xCF reserved for future operations

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

// Extended Opcodes - using two-byte opcode space
// The first byte indicates the extended category, the second is the operation
// These constants represent the high byte for extended opcode categories
const (
	// Extended opcode category markers
	ExtendedOpcodePXE    byte = 0x01 // PXE Extended Operations (0x01XX range)
	ExtendedOpcodeTenant byte = 0x02 // Tenant Operations (0x02XX range)
)

// PXE Extended Opcodes (using extended opcode space via two-byte opcodes)
// These use the high byte 0x01 to indicate extended opcodes
const (
	// Extended PXE Operations (0x01XX range)
	OpPXEStatus            byte = 0x00 // Use with extended flag
	OpPXEStart             byte = 0x01 // Use with extended flag
	OpPXEStop              byte = 0x02 // Use with extended flag
	OpPXEWebhookComplete   byte = 0x03 // Use with extended flag
	OpPXEGetDeviceByMAC    byte = 0x04 // Use with extended flag
	OpPXESetDeviceEnrolled byte = 0x05 // Use with extended flag
	OpPXEGetEvents         byte = 0x06 // Use with extended flag
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
	OpTenantValidateVLAN byte = 0xE7 // Validate VLAN for tenant
	OpTenantGetBridge    byte = 0xE8 // Get OVS bridge name
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
		return fmt.Errorf("request cannot be nil")
	}

	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxTokenSize {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxTokenSize)
	}

	// Write opcode
	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return fmt.Errorf("failed to write opcode: %w", err)
	}

	// Write token length (big-endian, 2 bytes)
	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	// Write token
	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	// Write payload length (big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// ReadRequest reads a request from the stream
func ReadRequest(r io.Reader) (*Request, error) {
	// Read opcode
	opcodeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, opcodeBuf); err != nil {
		return nil, fmt.Errorf("failed to read opcode: %w", err)
	}

	// Read token length
	tokenLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, tokenLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read token length: %w", err)
	}
	tokenLen := binary.BigEndian.Uint16(tokenLenBuf)

	if tokenLen > MaxTokenSize {
		return nil, fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxTokenSize)
	}

	// Read token
	var token string
	if tokenLen > 0 {
		tokenBuf := make([]byte, tokenLen)
		if _, err := io.ReadFull(r, tokenBuf); err != nil {
			return nil, fmt.Errorf("failed to read token: %w", err)
		}
		token = string(tokenBuf)
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &Request{
		Opcode:  opcodeBuf[0],
		Token:   token,
		Payload: payload,
	}, nil
}

// WriteResponse writes a response to the stream
func WriteResponse(w io.Writer, resp *Response) error {
	if resp == nil {
		return fmt.Errorf("response cannot be nil")
	}

	payloadLen := uint32(len(resp.Payload))
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	// Write status
	if _, err := w.Write([]byte{resp.Status}); err != nil {
		return fmt.Errorf("failed to write status: %w", err)
	}

	// Write payload length (big-endian)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(resp.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// ReadResponse reads a response from the stream
func ReadResponse(r io.Reader) (*Response, error) {
	// Read status
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxPayloadSize)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
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
		return nil, fmt.Errorf("no codec available for encoding")
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// DecodePayload decodes bytes into an entity using the configured codec
func DecodePayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c := getCodec()
	if c == nil {
		return fmt.Errorf("no codec available for decoding")
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
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
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// DecodePayloadWithCodec decodes bytes into an entity using a specific codec type
func DecodePayloadWithCodec(data []byte, entity interface{}, codecType codec.Type) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c, err := factory.New[any](codecType)
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

// OpcodeToString returns a human-readable name for an opcode
func OpcodeToString(opcode byte) string {
	switch opcode {
	// Health
	case OpHealth:
		return "Health"
	case OpLiveness:
		return "Liveness"
	case OpReadiness:
		return "Readiness"

	// vTPM Extended Operations
	case OpVTPMCreateTemplate:
		return "VTPMCreateTemplate"
	case OpVTPMGetTemplate:
		return "VTPMGetTemplate"
	case OpVTPMDeleteTemplate:
		return "VTPMDeleteTemplate"
	case OpVTPMListTemplates:
		return "VTPMListTemplates"
	case OpVTPMCloneTemplate:
		return "VTPMCloneTemplate"
	case OpVTPMExportBundle:
		return "VTPMExportBundle"
	case OpVTPMImportBundle:
		return "VTPMImportBundle"
	case OpVTPMValidateBundle:
		return "VTPMValidateBundle"
	case OpVTPMGetBundlePath:
		return "VTPMGetBundlePath"
	case OpVTPMGetSocketPath:
		return "VTPMGetSocketPath"
	case OpVTPMGetNVRAMPath:
		return "VTPMGetNVRAMPath"
	case OpVTPMGetBundle:
		return "VTPMGetBundle"
	case OpVTPMIsRunning:
		return "VTPMIsRunning"

	// vTPM
	case OpVTPMCreate:
		return "VTPMCreate"
	case OpVTPMDelete:
		return "VTPMDelete"
	case OpVTPMStart:
		return "VTPMStart"
	case OpVTPMStop:
		return "VTPMStop"
	case OpVTPMGetState:
		return "VTPMGetState"
	case OpVTPMList:
		return "VTPMList"
	case OpVTPMGetEK:
		return "VTPMGetEK"
	case OpVTPMGetAK:
		return "VTPMGetAK"
	case OpVTPMCreateAK:
		return "VTPMCreateAK"
	case OpVTPMQuote:
		return "VTPMQuote"
	case OpVTPMVerifyQuote:
		return "VTPMVerifyQuote"
	case OpVTPMExtendPCR:
		return "VTPMExtendPCR"
	case OpVTPMReadPCR:
		return "VTPMReadPCR"
	case OpVTPMSeal:
		return "VTPMSeal"
	case OpVTPMUnseal:
		return "VTPMUnseal"
	case OpVTPMGetRandom:
		return "VTPMGetRandom"

	// DNS
	case OpDNSAddRecord:
		return "DNSAddRecord"
	case OpDNSDeleteRecord:
		return "DNSDeleteRecord"
	case OpDNSUpdateRecord:
		return "DNSUpdateRecord"
	case OpDNSGetRecord:
		return "DNSGetRecord"
	case OpDNSListRecords:
		return "DNSListRecords"
	case OpDNSAddZone:
		return "DNSAddZone"
	case OpDNSDeleteZone:
		return "DNSDeleteZone"
	case OpDNSGetZone:
		return "DNSGetZone"
	case OpDNSListZones:
		return "DNSListZones"
	case OpDNSResolve:
		return "DNSResolve"
	case OpDNSGetConfig:
		return "DNSGetConfig"
	case OpDNSUpdateConfig:
		return "DNSUpdateConfig"
	case OpDNSGetMetrics:
		return "DNSGetMetrics"
	case OpDNSFlushCache:
		return "DNSFlushCache"
	case OpOverlayCategory:
		return "OverlayCategory"
	case OpGatewayCategory:
		return "GatewayCategory"

	// Device
	case OpDeviceRegister:
		return "DeviceRegister"
	case OpDeviceUnregister:
		return "DeviceUnregister"
	case OpDeviceGet:
		return "DeviceGet"
	case OpDeviceList:
		return "DeviceList"
	case OpDeviceUpdate:
		return "DeviceUpdate"
	case OpDeviceGetProfile:
		return "DeviceGetProfile"
	case OpDeviceSetProfile:
		return "DeviceSetProfile"
	case OpDeviceListProfiles:
		return "DeviceListProfiles"
	case OpDeviceCreateProfile:
		return "DeviceCreateProfile"
	case OpDeviceDeleteProfile:
		return "DeviceDeleteProfile"
	case OpDeviceAttest:
		return "DeviceAttest"
	case OpDeviceActivate:
		return "DeviceActivate"
	case OpDeviceDeactivate:
		return "DeviceDeactivate"
	case OpDeviceGetState:
		return "DeviceGetState"
	case OpDeviceGetMetrics:
		return "DeviceGetMetrics"
	case OpIPAMCategory:
		return "IPAMCategory"

	// SDN
	case OpSDNGetPortState:
		return "SDNGetPortState"
	case OpSDNSetPortState:
		return "SDNSetPortState"
	case OpSDNListPorts:
		return "SDNListPorts"
	case OpSDNGetFlow:
		return "SDNGetFlow"
	case OpSDNAddFlow:
		return "SDNAddFlow"
	case OpSDNDeleteFlow:
		return "SDNDeleteFlow"
	case OpSDNListFlows:
		return "SDNListFlows"
	case OpSDNApplyPolicy:
		return "SDNApplyPolicy"
	case OpSDNGetPolicy:
		return "SDNGetPolicy"
	case OpSDNListPolicies:
		return "SDNListPolicies"
	case OpSDNGetBridge:
		return "SDNGetBridge"
	case OpSDNListBridges:
		return "SDNListBridges"
	case OpSDNGetMetrics:
		return "SDNGetMetrics"
	case OpSDNSetVLAN:
		return "SDNSetVLAN"
	case OpSDNGetVLAN:
		return "SDNGetVLAN"
	case OpSDNGetPort:
		return "SDNGetPort"
	case OpSDNCreateBridge:
		return "SDNCreateBridge"
	case OpSDNDeleteBridge:
		return "SDNDeleteBridge"
	case OpSDNCreatePort:
		return "SDNCreatePort"
	case OpSDNDeletePort:
		return "SDNDeletePort"
	case OpSDNDeletePolicy:
		return "SDNDeletePolicy"

	// Provisioning
	case OpProvFetchProfile:
		return "ProvFetchProfile"
	case OpProvActivate:
		return "ProvActivate"
	case OpProvDeactivate:
		return "ProvDeactivate"
	case OpProvGetState:
		return "ProvGetState"
	case OpProvEnroll:
		return "ProvEnroll"
	case OpProvRenew:
		return "ProvRenew"

	// IDevID/IAK Device Identity
	case OpIDevIDGenerate:
		return "IDevIDGenerate"
	case OpIDevIDInfo:
		return "IDevIDInfo"
	case OpIDevIDDelete:
		return "IDevIDDelete"
	case OpIDevIDCSR:
		return "IDevIDCSR"
	case OpIDevIDInstallCert:
		return "IDevIDInstallCert"
	case OpIDevIDGetCert:
		return "IDevIDGetCert"
	case OpIAKGenerate:
		return "IAKGenerate"
	case OpIAKInfo:
		return "IAKInfo"
	case OpIAKDelete:
		return "IAKDelete"
	case OpIAKCSR:
		return "IAKCSR"
	case OpIAKInstallCert:
		return "IAKInstallCert"
	case OpIAKGetCert:
		return "IAKGetCert"
	case OpDeviceAttributes:
		return "DeviceAttributes"
	case OpActivateCredential:
		return "ActivateCredential"
	case OpHasIDevID:
		return "HasIDevID"
	case OpHasIAK:
		return "HasIAK"
	case OpIDevIDDeleteCert:
		return "IDevIDDeleteCert"
	case OpIAKDeleteCert:
		return "IAKDeleteCert"

	// VM
	case OpVMCreate:
		return "VMCreate"
	case OpVMDelete:
		return "VMDelete"
	case OpVMStart:
		return "VMStart"
	case OpVMStop:
		return "VMStop"
	case OpVMGet:
		return "VMGet"
	case OpVMList:
		return "VMList"
	case OpVMAttachNet:
		return "VMAttachNet"
	case OpVMDetachNet:
		return "VMDetachNet"
	case OpVMActivate:
		return "VMActivate"
	case OpVMDeactivate:
		return "VMDeactivate"
	case OpVMGetState:
		return "VMGetState"

	// Attestation
	case OpAttestQuote:
		return "AttestQuote"
	case OpAttestVerify:
		return "AttestVerify"
	case OpAttestGetEK:
		return "AttestGetEK"
	case OpAttestGetAK:
		return "AttestGetAK"
	case OpAttestChallenge:
		return "AttestChallenge"
	case OpAttestResponse:
		return "AttestResponse"
	case OpAttestGetReport:
		return "AttestGetReport"
	case OpAttestGetPCRs:
		return "AttestGetPCRs"

	// Certificate
	case OpCertIssue:
		return "CertIssue"
	case OpCertRevoke:
		return "CertRevoke"
	case OpCertRenew:
		return "CertRenew"
	case OpCertGet:
		return "CertGet"
	case OpCertList:
		return "CertList"
	case OpCertVerify:
		return "CertVerify"
	case OpCertGetChain:
		return "CertGetChain"
	case OpCertGetCRL:
		return "CertGetCRL"
	case OpCertGetOCSP:
		return "CertGetOCSP"

	// Daemon Management
	case OpDaemonStatus:
		return "DaemonStatus"
	case OpDaemonVersion:
		return "DaemonVersion"
	case OpDaemonListServices:
		return "DaemonListServices"
	case OpDaemonGetService:
		return "DaemonGetService"
	case OpDaemonStartService:
		return "DaemonStartService"
	case OpDaemonStopService:
		return "DaemonStopService"
	case OpDaemonRestartService:
		return "DaemonRestartService"
	case OpDaemonListProtocols:
		return "DaemonListProtocols"

	// TPM2 Category
	case OpTPM2Category:
		return "TPM2Category"
	// JWT/Auth
	case OpJWTCreate:
		return "JWTCreate"
	case OpJWTVerify:
		return "JWTVerify"
	case OpJWTRefresh:
		return "JWTRefresh"
	case OpJWTRevoke:
		return "JWTRevoke"
	case OpJWTGetKeys:
		return "JWTGetKeys"
	case OpAuthLogin:
		return "AuthLogin"
	case OpAuthLogout:
		return "AuthLogout"
	case OpAuthCheck:
		return "AuthCheck"

	// CA Operations
	case OpCAInfo:
		return "CAInfo"
	case OpCAIssue:
		return "CAIssue"
	case OpCARevoke:
		return "CARevoke"
	case OpCARenew:
		return "CARenew"
	case OpCAGet:
		return "CAGet"
	case OpCAList:
		return "CAList"
	case OpCAVerify:
		return "CAVerify"
	case OpCACRL:
		return "CACRL"
	case OpCABundle:
		return "CABundle"

	// IAM User Operations
	case OpIAMUserCreate:
		return "IAMUserCreate"
	case OpIAMUserDelete:
		return "IAMUserDelete"
	case OpIAMUserGet:
		return "IAMUserGet"
	case OpIAMUserList:
		return "IAMUserList"
	case OpIAMUserUpdate:
		return "IAMUserUpdate"

	// IAM Role Operations
	case OpIAMRoleCreate:
		return "IAMRoleCreate"
	case OpIAMRoleDelete:
		return "IAMRoleDelete"
	case OpIAMRoleGet:
		return "IAMRoleGet"
	case OpIAMRoleList:
		return "IAMRoleList"
	case OpIAMRoleAssign:
		return "IAMRoleAssign"
	case OpIAMRoleRevoke:
		return "IAMRoleRevoke"

	// IAM Group Operations
	case OpIAMGroupCreate:
		return "IAMGroupCreate"
	case OpIAMGroupDelete:
		return "IAMGroupDelete"
	case OpIAMGroupGet:
		return "IAMGroupGet"
	case OpIAMGroupList:
		return "IAMGroupList"
	case OpIAMGroupAddMember:
		return "IAMGroupAddMember"
	case OpIAMGroupRemoveMember:
		return "IAMGroupRemoveMember"

	// IAM Permission/Auth Operations
	case OpIAMCheckPermission:
		return "IAMCheckPermission"
	case OpIAMAuthenticate:
		return "IAMAuthenticate"
	case OpIAMTokenCreate:
		return "IAMTokenCreate"
	case OpIAMTokenRevoke:
		return "IAMTokenRevoke"
	case OpIAMTokenVerify:
		return "IAMTokenVerify"

	// KMS Key Management
	case OpKMSGenerateKey:
		return "KMSGenerateKey"
	case OpKMSImportKey:
		return "KMSImportKey"
	case OpKMSGetKey:
		return "KMSGetKey"
	case OpKMSListKeys:
		return "KMSListKeys"
	case OpKMSDeleteKey:
		return "KMSDeleteKey"
	case OpKMSRotateKey:
		return "KMSRotateKey"
	case OpKMSUpdateKeyStatus:
		return "KMSUpdateKeyStatus"
	case OpKMSExportKey:
		return "KMSExportKey"
	case OpKMSGetKeyVersions:
		return "KMSGetKeyVersions"
	case OpKMSBackendStatus:
		return "KMSBackendStatus"
	case OpKMSBatchEncrypt:
		return "KMSBatchEncrypt"
	case OpKMSBatchDecrypt:
		return "KMSBatchDecrypt"
	case OpSwitchCategory:
		return "SwitchCategory"

	// KMS Crypto Operations
	case OpKMSEncrypt:
		return "KMSEncrypt"
	case OpKMSDecrypt:
		return "KMSDecrypt"
	case OpKMSSign:
		return "KMSSign"
	case OpKMSVerify:
		return "KMSVerify"
	case OpKMSGenerateRandom:
		return "KMSGenerateRandom"
	case OpKMSHash:
		return "KMSHash"
	case OpKMSHMAC:
		return "KMSHMAC"
	case OpKMSVerifyHMAC:
		return "KMSVerifyHMAC"
	case OpKMSRewrap:
		return "KMSRewrap"
	case OpKMSGenerateDataKey:
		return "KMSGenerateDataKey"
	case OpKMSGenerateWrappedDataKey:
		return "KMSGenerateWrappedDataKey"

	// DEK Management
	case OpDEKCreate:
		return "DEKCreate"
	case OpDEKGet:
		return "DEKGet"
	case OpDEKList:
		return "DEKList"
	case OpDEKDelete:
		return "DEKDelete"
	case OpDEKRotate:
		return "DEKRotate"
	case OpDEKGetStatus:
		return "DEKGetStatus"

	// PXE Provisioning
	case OpPXEListDevices:
		return "PXEListDevices"
	case OpPXEGetDevice:
		return "PXEGetDevice"
	case OpPXERegisterDevice:
		return "PXERegisterDevice"
	case OpPXEUpdateState:
		return "PXEUpdateState"
	case OpPXEAuthorize:
		return "PXEAuthorize"
	case OpPXEQuarantine:
		return "PXEQuarantine"
	case OpPXERetry:
		return "PXERetry"
	case OpPXERemoveDevice:
		return "PXERemoveDevice"

	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// TenantOpcodeToString returns a human-readable name for a tenant opcode
func TenantOpcodeToString(opcode byte) string {
	switch opcode {
	case OpTenantList:
		return "TenantList"
	case OpTenantGet:
		return "TenantGet"
	case OpTenantGetByName:
		return "TenantGetByName"
	case OpTenantCreate:
		return "TenantCreate"
	case OpTenantUpdate:
		return "TenantUpdate"
	case OpTenantDelete:
		return "TenantDelete"
	case OpTenantSuspend:
		return "TenantSuspend"
	case OpTenantResume:
		return "TenantResume"
	case OpTenantGetQuotas:
		return "TenantGetQuotas"
	case OpTenantUpdateQuotas:
		return "TenantUpdateQuotas"
	case OpTenantGetUsage:
		return "TenantGetUsage"
	case OpTenantCheckQuota:
		return "TenantCheckQuota"
	case OpTenantValidateVLAN:
		return "TenantValidateVLAN"
	case OpTenantGetBridge:
		return "TenantGetBridge"
	case OpTenantSync:
		return "TenantSync"
	case OpTenantRotateDEK:
		return "TenantRotateDEK"
	case OpTenantGetDEKStatus:
		return "TenantGetDEKStatus"
	default:
		return fmt.Sprintf("UnknownTenantOp(0x%02X)", opcode)
	}
}

// StatusToString returns a human-readable name for a status code
func StatusToString(status byte) string {
	switch status {
	case StatusOK:
		return "OK"
	case StatusInvalidRequest:
		return "InvalidRequest"
	case StatusNotFound:
		return "NotFound"
	case StatusUnauthorized:
		return "Unauthorized"
	case StatusInternalError:
		return "InternalError"
	case StatusTimeout:
		return "Timeout"
	case StatusAlreadyExists:
		return "AlreadyExists"
	case StatusPermissionDenied:
		return "PermissionDenied"
	case StatusResourceExhausted:
		return "ResourceExhausted"
	case StatusInvalidArgument:
		return "InvalidArgument"
	case StatusUnavailable:
		return "Unavailable"
	case StatusNotImplemented:
		return "NotImplemented"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", status)
	}
}

// IsTenantOpcode checks if an opcode belongs to the tenant operation category
func IsTenantOpcode(opcode byte) bool {
	return opcode >= OpTenantList && opcode <= OpTenantGetDEKStatus
}
