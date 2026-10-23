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

package vtpm

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// NV RAM indices for EK certificates (TCG PC Client Platform spec)
const (
	// NVIndexRSAEKCert is the NV index for RSA EK certificates.
	NVIndexRSAEKCert uint32 = 0x01C00002

	// NVIndexECCEKCert is the NV index for ECC EK certificates.
	NVIndexECCEKCert uint32 = 0x01C0000A

	// DefaultNVBufferMax is the default maximum NV buffer size for writes.
	// Most TPMs support at least 1024 bytes per write.
	DefaultNVBufferMax uint16 = 1024
)

// EKCertInjector handles EK certificate injection into swtpm NV RAM.
// This uses go-xkms's transport layer for TPM communication.
type EKCertInjector struct {
	socketPath  string
	logger      *logging.Logger
	nvBufferMax uint16
}

// NewEKCertInjector creates a new EK certificate injector.
func NewEKCertInjector(socketPath string, logger *logging.Logger) *EKCertInjector {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &EKCertInjector{
		socketPath:  socketPath,
		logger:      logger,
		nvBufferMax: DefaultNVBufferMax,
	}
}

// SetNVBufferMax bounds the size of each NV_Write and NV_Read the injector
// issues. The TPM's own TPM_PT_NV_BUFFER_MAX still applies when it is
// smaller; zero leaves the TPM's value as the only bound.
func (e *EKCertInjector) SetNVBufferMax(size uint16) {
	e.nvBufferMax = size
}

// chunkSize returns the largest NV transfer the injector issues on t:
// TPM_PT_NV_BUFFER_MAX as the TPM reports it through TPM2_GetCapability
// (TPM 2.0 Part 2 §6.13), lowered to the injector's own bound when that is
// smaller. A TPM2_NV_Write or TPM2_NV_Read carrying more than the TPM's
// buffer maximum fails with TPM_RC_SIZE (TPM 2.0 Part 3 §31.7, §31.13);
// swtpm reports 1024 bytes, less than an RSA EK certificate can take.
func (e *EKCertInjector) chunkSize(t transport.TPM) (uint16, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return 0, ErrNVBufferMaxUnavailable{Cause: err}
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, ErrNVBufferMaxUnavailable{Cause: err}
	}
	if len(props.TPMProperty) == 0 || props.TPMProperty[0].Property != tpm2.TPMPTNVBufferMax ||
		props.TPMProperty[0].Value == 0 {
		return 0, ErrNVBufferMaxUnavailable{Cause: &MessageError{Msg: "the TPM did not report the property"}}
	}

	tpmMax := props.TPMProperty[0].Value
	if e.nvBufferMax != 0 && uint32(e.nvBufferMax) < tpmMax {
		return e.nvBufferMax, nil
	}
	if tpmMax > uint32(^uint16(0)) {
		return ^uint16(0), nil
	}
	return uint16(tpmMax), nil
}

// startup sends TPM2_Startup command to initialize the TPM.
// This is required before any other TPM commands can be executed.
func (e *EKCertInjector) startup(t transport.TPM) error {
	e.logger.Debug("Sending TPM2_Startup command")

	_, err := tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(t)
	if err != nil {
		// TPM_RC_INITIALIZE means TPM is already initialized, which is fine
		if tpmErr, ok := err.(tpm2.TPMRC); ok {
			// RC_INITIALIZE is 0x100 (format zero) - already initialized
			if uint32(tpmErr)&0x1FF == 0x100 {
				e.logger.Debug("TPM already initialized")
				return nil
			}
		}
		return ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "TPM2_Startup failed", Err: err}}
	}

	e.logger.Debug("TPM2_Startup completed successfully")
	return nil
}

// InjectCertificate writes an EK certificate to the appropriate NV index.
func (e *EKCertInjector) InjectCertificate(ctx context.Context, cert *x509.Certificate, algorithm EKAlgorithm) error {
	if cert == nil {
		return ErrEKCertInjectionFailed{Cause: &MessageError{Msg: "certificate cannot be nil"}}
	}

	// Open connection to swtpm socket using go-xkms's transport
	t, err := linuxudstpm.Open(e.socketPath)
	if err != nil {
		return ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to open swtpm socket", Err: err}}
	}
	defer t.Close()

	// Send TPM2_Startup command to initialize the TPM
	if err := e.startup(t); err != nil {
		return err
	}

	return e.writeCertificate(t, cert, algorithm)
}

// writeCertificate defines the EK certificate NV index for algorithm on the
// started TPM behind t and writes cert into it, one TPM2_NV_Write per
// chunkSize bytes at increasing offsets.
func (e *EKCertInjector) writeCertificate(t transport.TPM, cert *x509.Certificate, algorithm EKAlgorithm) error {
	if cert == nil {
		return ErrEKCertInjectionFailed{Cause: &MessageError{Msg: "certificate cannot be nil"}}
	}

	nvIndex := algorithm.NVIndex()
	certDER := cert.Raw

	e.logger.Info("Injecting EK certificate to NV RAM",
		"algorithm", string(algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
		"certSize", len(certDER))

	chunkSize, err := e.chunkSize(t)
	if err != nil {
		return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: err}
	}

	// Define the NV space
	if err := e.defineNVSpace(t, nvIndex, uint16(len(certDER))); err != nil {
		return err
	}

	// Get the NV index Name for authorization (required by go-tpm)
	nvName, err := e.getNVName(t, nvIndex)
	if err != nil {
		return err
	}

	// Write the certificate data
	if err := e.writeNVData(t, nvIndex, nvName, certDER, chunkSize); err != nil {
		return err
	}

	e.logger.Info("EK certificate injected successfully",
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex))

	return nil
}

// defineNVSpace defines the NV space for the EK certificate.
func (e *EKCertInjector) defineNVSpace(t transport.TPM, nvIndex uint32, size uint16) error {
	e.logger.Debug("Defining NV space",
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
		"size", size)

	// Create NV handle
	nvHandle := tpm2.TPMHandle(nvIndex)

	// Define NV attributes for EK certificate storage
	// TPMA_NV_PPWRITE: Platform hierarchy can write
	// TPMA_NV_PPREAD: Platform hierarchy can read
	// TPMA_NV_OWNERREAD: Owner hierarchy can read
	// TPMA_NV_AUTHREAD: Reads require authorization
	// TPMA_NV_NO_DA: Dictionary attack protection not applicable
	// TPMA_NV_PLATFORMCREATE: Created by platform hierarchy
	nvAttrs := tpm2.TPMANV{
		PPWrite:        true,
		PPRead:         true,
		OwnerRead:      true,
		AuthRead:       true,
		NoDA:           true,
		PlatformCreate: true,
	}

	// Create NV public area
	nvPublic := tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex:    nvHandle,
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: nvAttrs,
		DataSize:   size,
	})

	// Define the NV space using platform hierarchy
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHPlatform,
		PublicInfo: nvPublic,
	}.Execute(t)
	if err != nil {
		// Check if NV index already exists
		if isNVDefinedError(err) {
			e.logger.Debug("NV index already defined, undefining and redefining",
				"nvIndex", fmt.Sprintf("0x%08X", nvIndex))

			// Read existing NV public to get the Name for undefine
			existingPublic, readErr := tpm2.NVReadPublic{
				NVIndex: nvHandle,
			}.Execute(t)
			if readErr != nil {
				return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: &WrappedError{Msg: "failed to read existing NV public", Err: readErr}}
			}

			// Create named handle for undefine
			existingNVHandle := nvNamedHandle{
				handle: nvHandle,
				name:   existingPublic.NVName,
			}

			// Undefine existing NV space
			_, undefErr := tpm2.NVUndefineSpace{
				AuthHandle: tpm2.TPMRHPlatform,
				NVIndex:    existingNVHandle,
			}.Execute(t)
			if undefErr != nil {
				return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: &WrappedError{Msg: "failed to undefine existing NV space", Err: undefErr}}
			}

			// Retry define
			_, err = tpm2.NVDefineSpace{
				AuthHandle: tpm2.TPMRHPlatform,
				PublicInfo: nvPublic,
			}.Execute(t)
			if err != nil {
				return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: &WrappedError{Msg: "failed to define NV space after undefine", Err: err}}
			}
			return nil
		}
		return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: &WrappedError{Msg: "failed to define NV space", Err: err}}
	}

	return nil
}

// isNVDefinedError checks if the error indicates the NV index is already defined.
func isNVDefinedError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a TPMRC error
	if tpmErr, ok := err.(tpm2.TPMRC); ok {
		// TPM_RC_NV_DEFINED is 0x149 (format zero) or with format one bits
		// Check the base error code (lower 7 bits for format zero)
		code := uint32(tpmErr)
		// RC_NV_DEFINED has various representations:
		// - 0x149 (329) - base error code
		// - 0x94C - with format one session bits (unlikely for this error)
		// Mask off the format bits and check for 0x149 or related codes
		baseCode := code & 0x1FF // Get base error code
		if baseCode == 0x149 {
			return true
		}
		// Also check string representation as fallback
		return strings.Contains(err.Error(), "NV_DEFINED") ||
			strings.Contains(err.Error(), "already defined")
	}

	// Fallback to string matching for wrapped errors
	return strings.Contains(err.Error(), "NV_DEFINED") ||
		strings.Contains(err.Error(), "already defined")
}

// getNVName reads the NV public area and returns the Name.
// The Name is required for proper authorization in NV operations.
func (e *EKCertInjector) getNVName(t transport.TPM, nvIndex uint32) (tpm2.TPM2BName, error) {
	nvHandle := tpm2.TPMHandle(nvIndex)

	nvReadPublicResp, err := tpm2.NVReadPublic{
		NVIndex: nvHandle,
	}.Execute(t)
	if err != nil {
		return tpm2.TPM2BName{}, ErrEKCertInjectionFailed{
			Cause: &WrappedError{Msg: "failed to read NV public for Name", Err: err},
		}
	}

	e.logger.Debug("Got NV Name",
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
		"nameLen", len(nvReadPublicResp.NVName.Buffer))

	return nvReadPublicResp.NVName, nil
}

// nvNamedHandle wraps an NV index handle with its Name for authorization.
// It implements the tpm2.handle interface for use in NVWrite/NVRead commands.
type nvNamedHandle struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// HandleValue returns the TPM handle value as uint32 (required by go-tpm).
func (n nvNamedHandle) HandleValue() uint32 {
	return uint32(n.handle)
}

// KnownName returns the NV index Name for authorization.
func (n nvNamedHandle) KnownName() *tpm2.TPM2BName {
	return &n.name
}

// writeNVData writes data to the NV space in chunks.
func (e *EKCertInjector) writeNVData(t transport.TPM, nvIndex uint32, nvName tpm2.TPM2BName, data []byte, maxChunk uint16) error {
	// Create a named handle for authorization
	nvHandle := nvNamedHandle{
		handle: tpm2.TPMHandle(nvIndex),
		name:   nvName,
	}

	// Write data in chunks of at most maxChunk bytes
	offset := uint16(0)
	remaining := len(data)

	for remaining > 0 {
		chunkSize := int(maxChunk)
		if remaining < chunkSize {
			chunkSize = remaining
		}

		chunk := data[offset : offset+uint16(chunkSize)]

		e.logger.Debug("Writing NV chunk",
			"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
			"offset", offset,
			"chunkSize", chunkSize,
			"remaining", remaining)

		_, err := tpm2.NVWrite{
			AuthHandle: tpm2.TPMRHPlatform,
			NVIndex:    nvHandle,
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: chunk,
			},
			Offset: offset,
		}.Execute(t)
		if err != nil {
			return ErrNVRAMWriteFailed{NVIndex: nvIndex, Cause: &WrappedError{Msg: fmt.Sprintf("failed to write NV data at offset %d", offset), Err: err}}
		}

		offset += uint16(chunkSize)
		remaining -= chunkSize
	}

	return nil
}

// ReadCertificate reads an EK certificate from NV RAM.
func (e *EKCertInjector) ReadCertificate(ctx context.Context, algorithm EKAlgorithm) (*x509.Certificate, error) {
	nvIndex := algorithm.NVIndex()

	e.logger.Debug("Reading EK certificate from NV RAM",
		"algorithm", string(algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex))

	// Open connection to swtpm socket using go-xkms's transport
	t, err := linuxudstpm.Open(e.socketPath)
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to open swtpm socket", Err: err}}
	}
	defer t.Close()

	// Send TPM2_Startup command to initialize the TPM (may already be initialized)
	if err := e.startup(t); err != nil {
		return nil, err
	}

	return e.readCertificate(t, nvIndex)
}

// readCertificate reads the certificate stored at nvIndex on the started TPM
// behind t, one TPM2_NV_Read per chunkSize bytes.
func (e *EKCertInjector) readCertificate(t transport.TPM, nvIndex uint32) (*x509.Certificate, error) {
	// First, read the NV public to get the size and Name
	nvHandle := tpm2.TPMHandle(nvIndex)

	nvReadPublicResp, err := tpm2.NVReadPublic{
		NVIndex: nvHandle,
	}.Execute(t)
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to read NV public", Err: err}}
	}

	nvPublicContents, err := nvReadPublicResp.NVPublic.Contents()
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to get NV public contents", Err: err}}
	}
	dataSize := nvPublicContents.DataSize

	// Create named handle for authorization
	nvNamedHdl := nvNamedHandle{
		handle: nvHandle,
		name:   nvReadPublicResp.NVName,
	}

	maxChunk, err := e.chunkSize(t)
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: err}
	}

	// Read the data in chunks
	data := make([]byte, 0, dataSize)
	offset := uint16(0)

	for offset < dataSize {
		chunkSize := maxChunk
		if dataSize-offset < chunkSize {
			chunkSize = dataSize - offset
		}

		resp, err := tpm2.NVRead{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    nvNamedHdl,
			Size:       chunkSize,
			Offset:     offset,
		}.Execute(t)
		if err != nil {
			return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: fmt.Sprintf("failed to read NV data at offset %d", offset), Err: err}}
		}

		data = append(data, resp.Data.Buffer...)
		offset += chunkSize
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to parse certificate", Err: err}}
	}

	return cert, nil
}

// VerifyCertificate reads back and verifies the stored certificate matches.
func (e *EKCertInjector) VerifyCertificate(ctx context.Context, expected *x509.Certificate, algorithm EKAlgorithm) error {
	actual, err := e.ReadCertificate(ctx, algorithm)
	if err != nil {
		return err
	}

	if !actual.Equal(expected) {
		return ErrEKCertInjectionFailed{Cause: &MessageError{Msg: "certificate verification failed: stored certificate does not match"}}
	}

	e.logger.Info("EK certificate verification successful",
		"nvIndex", fmt.Sprintf("0x%08X", algorithm.NVIndex()))

	return nil
}

// CheckEKCertificateExists checks if an EK certificate exists at the NV index
// for the specified algorithm. This is a CRITICAL safety check that MUST be
// called before any EK certificate provisioning to prevent overwriting
// manufacturer-provisioned EK certificates.
//
// Returns:
//   - exists: true if a certificate is present at the NV index
//   - cert: the certificate if it exists, nil otherwise
//   - err: error if the check itself failed (NV index not existing is NOT an error)
//
// SAFETY: If this returns exists=true, you MUST NOT provision a new EK certificate.
// Overwriting an EK certificate on a real TPM could permanently damage it.
func (e *EKCertInjector) CheckEKCertificateExists(ctx context.Context, algorithm EKAlgorithm) (bool, *x509.Certificate, error) {
	nvIndex := algorithm.NVIndex()

	e.logger.Debug("Checking if EK certificate exists in NV RAM",
		"algorithm", string(algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex))

	// Open connection to swtpm socket using go-xkms's transport
	t, err := linuxudstpm.Open(e.socketPath)
	if err != nil {
		return false, nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to open swtpm socket", Err: err}}
	}
	defer t.Close()

	// Send TPM2_Startup command to initialize the TPM (may already be initialized)
	if err := e.startup(t); err != nil {
		return false, nil, err
	}

	// Try to read the NV public area - if it doesn't exist, the NV index is undefined
	nvHandle := tpm2.TPMHandle(nvIndex)

	nvReadPublicResp, err := tpm2.NVReadPublic{
		NVIndex: nvHandle,
	}.Execute(t)
	if err != nil {
		// Check if error indicates NV index doesn't exist
		if isNVUndefinedError(err) {
			e.logger.Debug("NV index not defined - no EK certificate present",
				"nvIndex", fmt.Sprintf("0x%08X", nvIndex))
			return false, nil, nil
		}
		// Some other error occurred
		return false, nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to read NV public", Err: err}}
	}

	// NV index exists, now try to read the certificate data
	nvPublicContents, err := nvReadPublicResp.NVPublic.Contents()
	if err != nil {
		return false, nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to get NV public contents", Err: err}}
	}
	dataSize := nvPublicContents.DataSize

	// If data size is 0, the NV index exists but is empty
	if dataSize == 0 {
		e.logger.Debug("NV index exists but is empty - no EK certificate present",
			"nvIndex", fmt.Sprintf("0x%08X", nvIndex))
		return false, nil, nil
	}

	// Create named handle for authorization
	nvNamedHdl := nvNamedHandle{
		handle: nvHandle,
		name:   nvReadPublicResp.NVName,
	}

	maxChunk, err := e.chunkSize(t)
	if err != nil {
		return false, nil, ErrEKCertInjectionFailed{Cause: err}
	}

	// Read the data in chunks
	data := make([]byte, 0, dataSize)
	offset := uint16(0)

	for offset < dataSize {
		chunkSize := maxChunk
		if dataSize-offset < chunkSize {
			chunkSize = dataSize - offset
		}

		resp, err := tpm2.NVRead{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    nvNamedHdl,
			Size:       chunkSize,
			Offset:     offset,
		}.Execute(t)
		if err != nil {
			return false, nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: fmt.Sprintf("failed to read NV data at offset %d", offset), Err: err}}
		}

		data = append(data, resp.Data.Buffer...)
		offset += chunkSize
	}

	// Try to parse the certificate
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		// Data exists but isn't a valid certificate
		e.logger.Debug("NV index contains data but not a valid certificate",
			"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
			"dataSize", dataSize,
			"error", err.Error())
		// We still consider this as "exists" because the NV space is defined and has data
		// The caller should NOT overwrite it
		return true, nil, nil
	}

	e.logger.Info("EK certificate exists in NV RAM",
		"algorithm", string(algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", nvIndex),
		"subject", cert.Subject.CommonName)

	return true, cert, nil
}

// isNVUndefinedError checks if the error indicates the NV index does not exist.
func isNVUndefinedError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a TPMRC error
	if tpmErr, ok := err.(tpm2.TPMRC); ok {
		// TPM_RC_HANDLE is 0x08B (139) - handle out of range or undefined
		// TPM_RC_NV_UNDEFINED is for undefined NV index
		code := uint32(tpmErr)
		baseCode := code & 0x1FF // Get base error code

		// RC_HANDLE = 0x08B (139) - used when NV index doesn't exist
		// RC_NV_UNDEFINED might also be returned
		if baseCode == 0x08B || baseCode == 0x14B {
			return true
		}

		// Also check string representation as fallback
		errStr := err.Error()
		return strings.Contains(errStr, "HANDLE") ||
			strings.Contains(errStr, "NV_UNDEFINED") ||
			strings.Contains(errStr, "handle")
	}

	// Fallback to string matching for wrapped errors
	errStr := err.Error()
	return strings.Contains(errStr, "HANDLE") ||
		strings.Contains(errStr, "NV_UNDEFINED") ||
		strings.Contains(errStr, "handle") ||
		strings.Contains(errStr, "undefined")
}
