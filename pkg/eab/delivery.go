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

package eab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/url"
	"os"
	"path/filepath"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// DeliveryConfig contains configuration for credential delivery.
type DeliveryConfig struct {
	// BaseURL is the base URL for enrollment (e.g., "https://acme.example.com")
	BaseURL string
	// QRCodeSize is the size in pixels for QR code generation (default: 256)
	QRCodeSize int
}

// DefaultDeliveryConfig returns a DeliveryConfig with sensible defaults.
func DefaultDeliveryConfig() DeliveryConfig {
	return DeliveryConfig{
		QRCodeSize: 256,
	}
}

// Delivery provides methods for delivering EAB credentials to devices.
type Delivery struct {
	config DeliveryConfig
}

// NewDelivery creates a new credential delivery handler.
func NewDelivery(config DeliveryConfig) *Delivery {
	if config.QRCodeSize <= 0 {
		config.QRCodeSize = 256
	}
	return &Delivery{config: config}
}

// ExportedCredential is the JSON structure for exported credentials.
type ExportedCredential struct {
	KeyID     string `json:"kid"`
	HMACKey   string `json:"hmac_key"`
	ProfileID uint64 `json:"profile_id"`
	TenantID  string `json:"tenant_id"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// ToQRCode generates a QR code image containing the EAB credentials.
// The QR code contains a JSON payload with the KeyID and HMAC key (base64 encoded).
func (d *Delivery) ToQRCode(cred *Credential) ([]byte, error) {
	exported := d.credentialToExported(cred)

	jsonData, err := json.Marshal(exported)
	if err != nil {
		return nil, ErrQRCodeGenerationFailed{Cause: err}
	}

	qrCode, err := qr.Encode(string(jsonData), qr.M, qr.Auto)
	if err != nil {
		return nil, ErrQRCodeGenerationFailed{Cause: err}
	}

	qrCode, err = barcode.Scale(qrCode, d.config.QRCodeSize, d.config.QRCodeSize)
	if err != nil {
		return nil, ErrQRCodeGenerationFailed{Cause: err}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, qrCode); err != nil {
		return nil, ErrQRCodeGenerationFailed{Cause: err}
	}

	return buf.Bytes(), nil
}

// ToQRCodeFile generates a QR code and writes it to a file.
func (d *Delivery) ToQRCodeFile(cred *Credential, path string) error {
	data, err := d.ToQRCode(cred)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ErrFileExportFailed{Path: path, Cause: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return ErrFileExportFailed{Path: path, Cause: err}
	}

	return nil
}

// ToFile exports the credential as a JSON file.
func (d *Delivery) ToFile(cred *Credential, path string) error {
	exported := d.credentialToExported(cred)

	jsonData, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		return ErrFileExportFailed{Path: path, Cause: err}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ErrFileExportFailed{Path: path, Cause: err}
	}

	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return ErrFileExportFailed{Path: path, Cause: err}
	}

	return nil
}

// ToJSON exports the credential as a JSON byte slice.
func (d *Delivery) ToJSON(cred *Credential) ([]byte, error) {
	exported := d.credentialToExported(cred)
	return json.Marshal(exported)
}

// ToURL generates an enrollment URL with embedded credentials.
// The URL contains the KeyID and HMAC key as query parameters.
func (d *Delivery) ToURL(cred *Credential) (string, error) {
	if d.config.BaseURL == "" {
		return "", ErrInvalidCredential{Reason: "base URL not configured"}
	}

	baseURL, err := url.Parse(d.config.BaseURL)
	if err != nil {
		return "", ErrInvalidCredential{Reason: "invalid base URL: " + err.Error()}
	}

	query := baseURL.Query()
	query.Set("kid", cred.KeyID)
	query.Set("hmac", base64.RawURLEncoding.EncodeToString(cred.HMACKey))
	if cred.ProfileID > 0 {
		query.Set("profile", string(rune(cred.ProfileID)))
	}
	baseURL.RawQuery = query.Encode()

	return baseURL.String(), nil
}

// ToURLWithPath generates an enrollment URL with a specific path and embedded credentials.
func (d *Delivery) ToURLWithPath(cred *Credential, path string) (string, error) {
	if d.config.BaseURL == "" {
		return "", ErrInvalidCredential{Reason: "base URL not configured"}
	}

	baseURL, err := url.Parse(d.config.BaseURL)
	if err != nil {
		return "", ErrInvalidCredential{Reason: "invalid base URL: " + err.Error()}
	}

	baseURL.Path = path

	query := baseURL.Query()
	query.Set("kid", cred.KeyID)
	query.Set("hmac", base64.RawURLEncoding.EncodeToString(cred.HMACKey))
	baseURL.RawQuery = query.Encode()

	return baseURL.String(), nil
}

// credentialToExported converts a Credential to an ExportedCredential.
func (d *Delivery) credentialToExported(cred *Credential) ExportedCredential {
	exported := ExportedCredential{
		KeyID:     cred.KeyID,
		HMACKey:   base64.RawURLEncoding.EncodeToString(cred.HMACKey),
		ProfileID: cred.ProfileID,
		TenantID:  cred.TenantID,
	}
	if !cred.ExpiresAt.IsZero() {
		exported.ExpiresAt = cred.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}
	return exported
}

// ParseExportedCredential parses JSON data into an ExportedCredential.
func ParseExportedCredential(data []byte) (*ExportedCredential, error) {
	var exported ExportedCredential
	if err := json.Unmarshal(data, &exported); err != nil {
		return nil, ErrInvalidCredential{Reason: "invalid JSON: " + err.Error()}
	}
	return &exported, nil
}

// DecodeHMACKey decodes the base64-encoded HMAC key from an ExportedCredential.
func (e *ExportedCredential) DecodeHMACKey() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(e.HMACKey)
}
