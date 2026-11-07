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

package app

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrTPMCertStoreNotConfigured is returned when a certificate must go to the
// TPM certificate store and the platform has none.
var ErrTPMCertStoreNotConfigured = errors.New("trusted-platform: the TPM certificate store is not configured")

// errNVLimitNotReported is the cause of an NVLimitError when the TPM answers
// TPM2_GetCapability without the requested NV limit property.
var errNVLimitNotReported = errors.New("the TPM did not report the property")

// NVLimitError reports that an NV size limit (TPM_PT_NV_INDEX_MAX or
// TPM_PT_NV_BUFFER_MAX) could not be read, so the platform cannot tell
// whether a certificate can be written to an NV index.
type NVLimitError struct {
	Property string
	Err      error
}

func (e *NVLimitError) Error() string {
	return "reading " + e.Property + ": " + e.Err.Error()
}

func (e *NVLimitError) Unwrap() error {
	return e.Err
}

// EKCertNVWriteError reports that the EK certificate fits an NV index but
// writing it there failed. The certificate is not moved to the certificate
// store instead: a TPM that cannot write its NV is reported, not hidden.
type EKCertNVWriteError struct {
	Size int
	Err  error
}

func (e *EKCertNVWriteError) Error() string {
	return fmt.Sprintf("writing the %d-byte EK certificate to TPM NV: %v", e.Size, e.Err)
}

func (e *EKCertNVWriteError) Unwrap() error {
	return e.Err
}

// nvIndexMax returns TPM_PT_NV_INDEX_MAX, the largest data area one NV index
// can hold (TPM 2.0 Part 2 §6.13).
func nvIndexMax(t transport.TPM) (uint32, error) {
	return nvLimit(t, tpm2.TPMPTNVIndexMax, "TPM_PT_NV_INDEX_MAX")
}

// nvBufferMax returns TPM_PT_NV_BUFFER_MAX, the most data one TPM2_NV_Write
// can carry (TPM 2.0 Part 2 §6.13, Part 3 §31.7).
func nvBufferMax(t transport.TPM) (uint32, error) {
	return nvLimit(t, tpm2.TPMPTNVBufferMax, "TPM_PT_NV_BUFFER_MAX")
}

// nvLimit reads one non-zero NV size property through TPM2_GetCapability
// (TPM 2.0 Part 3 §30.2).
func nvLimit(t transport.TPM, property tpm2.TPMPT, name string) (uint32, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(property),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return 0, &NVLimitError{Property: name, Err: err}
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, &NVLimitError{Property: name, Err: err}
	}
	if len(props.TPMProperty) == 0 || props.TPMProperty[0].Property != property ||
		props.TPMProperty[0].Value == 0 {
		return 0, &NVLimitError{Property: name, Err: errNVLimitNotReported}
	}
	return props.TPMProperty[0].Value, nil
}

// provisionEKCertificate persists the EK certificate where it fits (#81).
//
// With `tpm.ek.cert-handle` set, a certificate no larger than both
// TPM_PT_NV_INDEX_MAX and TPM_PT_NV_BUFFER_MAX goes to NV: go-xkms defines it
// at the RSA 2048 EK certificate index of the TCG EK Credential Profile v2.1
// §2.2.1.4 (0x01C00002). go-xkms ProvisionEKCert writes the whole certificate
// in a single TPM2_NV_Write, which the TPM refuses above TPM_PT_NV_BUFFER_MAX,
// so a certificate larger than either limit goes to the TPM certificate store.
// go-xkms reads the EK certificate from the configured index, then the
// §2.2.1.4 indices, then the certificate store, so the read finds it wherever
// it was written.
//
// An NV write that fails is returned as an EKCertNVWriteError: it never
// falls back to the certificate store. Without a cert-handle go-xkms writes
// the certificate store itself.
func (app *App) provisionEKCertificate(hierarchyAuth []byte, ekAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate) error {
	if app.TPMConfig.EK == nil || app.TPMConfig.EK.CertHandle == 0 {
		return app.TPM.ProvisionEKCert(hierarchyAuth, ekCert.Raw)
	}

	indexMax, err := nvIndexMax(app.TPM.Transport())
	if err != nil {
		return err
	}
	bufferMax, err := nvBufferMax(app.TPM.Transport())
	if err != nil {
		return err
	}
	if uint32(len(ekCert.Raw)) > min(indexMax, bufferMax) { // #nosec G115 -- a DER certificate is far below 4 GiB
		if app.TPMCertStore == nil {
			return ErrTPMCertStoreNotConfigured
		}
		app.Logger.Info("EK certificate is larger than one TPM NV write; storing it in the TPM certificate store",
			slog.Int("size_bytes", len(ekCert.Raw)),
			slog.Int("nv_index_max", int(indexMax)),
			slog.Int("nv_buffer_max", int(bufferMax)))
		return app.TPMCertStore.Save(ekAttrs, ekCert)
	}

	if err := app.TPM.ProvisionEKCert(hierarchyAuth, ekCert.Raw); err != nil {
		return &EKCertNVWriteError{Size: len(ekCert.Raw), Err: err}
	}
	return nil
}
