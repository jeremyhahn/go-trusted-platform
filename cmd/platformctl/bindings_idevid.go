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

package main

import (
	"log/slog"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// IDevIDBinding exposes IDevID and IAK service methods to the Wails frontend.
type IDevIDBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewIDevIDBinding creates a new IDevIDBinding.
func NewIDevIDBinding(logger *slog.Logger, conn *ConnectionBinding) *IDevIDBinding {
	return &IDevIDBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *IDevIDBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GenerateIDevID creates a new IDevID key in the TPM.
func (b *IDevIDBinding) GenerateIDevID() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GenerateIDevID(b.conn.ctx, &platformv1.GenerateIDevIDRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetIDevIDInfo retrieves information about the IDevID key.
func (b *IDevIDBinding) GetIDevIDInfo() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GetIDevIDInfo(b.conn.ctx, &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// HasIDevID checks if an IDevID key exists in the TPM.
func (b *IDevIDBinding) HasIDevID() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().HasIDevID(b.conn.ctx, &platformv1.HasIDevIDRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteIDevID asks the daemon to delete the IDevID key. The daemon refuses
// with FailedPrecondition on every transport and the key stays in the TPM;
// the refusal is returned as the error.
func (b *IDevIDBinding) DeleteIDevID() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().DeleteIDevID(b.conn.ctx, &platformv1.DeleteIDevIDRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GenerateIAK creates a new IAK (Initial Attestation Key) in the TPM.
func (b *IDevIDBinding) GenerateIAK() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GenerateIAK(b.conn.ctx, &platformv1.GenerateIAKRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetIAKInfo retrieves information about the IAK key.
func (b *IDevIDBinding) GetIAKInfo() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GetIAKInfo(b.conn.ctx, &platformv1.GetIAKInfoRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// HasIAK checks if an IAK key exists in the TPM.
func (b *IDevIDBinding) HasIAK() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().HasIAK(b.conn.ctx, &platformv1.HasIAKRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteIAK asks the daemon to delete the IAK. The daemon refuses with
// FailedPrecondition on every transport and the key stays in the TPM; the
// refusal is returned as the error.
func (b *IDevIDBinding) DeleteIAK() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().DeleteIAK(b.conn.ctx, &platformv1.DeleteIAKRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CreateIDevIDCSR creates a certificate signing request for the IDevID key.
func (b *IDevIDBinding) CreateIDevIDCSR() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().CreateIDevIDCSR(b.conn.ctx, &platformv1.CreateIDevIDCSRRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// InstallIDevIDCertificate installs an IDevID certificate.
func (b *IDevIDBinding) InstallIDevIDCertificate(certificatePEM []byte) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().InstallIDevIDCertificate(b.conn.ctx, &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: certificatePEM,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetIDevIDCertificate retrieves the installed IDevID certificate.
func (b *IDevIDBinding) GetIDevIDCertificate() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GetIDevIDCertificate(b.conn.ctx, &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetDeviceAttributes retrieves TCG device attributes from TPM and platform.
func (b *IDevIDBinding) GetDeviceAttributes() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IDevID().GetDeviceAttributes(b.conn.ctx, &platformv1.GetDeviceAttributesRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
