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

package uefi

import (
	"crypto/x509"
	"encoding/binary"
	"os"
	"path/filepath"
)

// ErrEfivarRead reports a failure reading or parsing an EFI variable from
// efivarfs. Var identifies the variable (SetupMode, SecureBoot, PK, ...).
type ErrEfivarRead struct {
	Var   string
	Cause error
}

func (e *ErrEfivarRead) Error() string {
	return "uefi: failed to read efi variable " + e.Var + ": " + e.Cause.Error()
}

func (e *ErrEfivarRead) Unwrap() error { return e.Cause }

// SignatureDatabase summarizes the contents of one Secure Boot signature
// database variable (PK, KEK, db, or dbx) as read from efivarfs.
type SignatureDatabase struct {
	// Name is the EFI variable name (PK, KEK, db, dbx).
	Name string `json:"name" yaml:"name"`

	// Present reports whether the variable exists in efivarfs.
	Present bool `json:"present" yaml:"present"`

	// Certificates is the number of X.509 entries across all signature lists.
	Certificates int `json:"certificates" yaml:"certificates"`

	// Hashes is the number of SHA-256 hash entries across all signature lists.
	Hashes int `json:"hashes" yaml:"hashes"`

	// Other is the number of entries whose signature type is neither X.509
	// nor SHA-256.
	Other int `json:"other" yaml:"other"`

	// Subjects holds the X.509 subject of each parseable certificate entry.
	Subjects []string `json:"subjects,omitempty" yaml:"subjects,omitempty"`
}

// SecureBootStatus is the read-side view of the firmware Secure Boot state,
// assembled from efivarfs. It is the bare-metal counterpart to the OVMF
// EnrollmentStatus produced by the NVRAM-file enroller.
type SecureBootStatus struct {
	// EfivarsAvailable reports whether the efivarfs pseudo-filesystem is
	// mounted (the system booted in UEFI mode with efivarfs support).
	EfivarsAvailable bool `json:"efivars_available" yaml:"efivars_available"`

	// SetupMode reports whether the firmware is in Setup Mode (no active PK;
	// raw key enrollment permitted).
	SetupMode bool `json:"setup_mode" yaml:"setup_mode"`

	// SecureBoot reports whether the firmware currently enforces Secure Boot.
	SecureBoot bool `json:"secure_boot" yaml:"secure_boot"`

	// UserMode reports whether the firmware is in User Mode: a PK is enrolled
	// and the firmware has left Setup Mode. It is derived per UEFI spec §32.3
	// (SetupMode == 0 with a Platform Key present).
	UserMode bool `json:"user_mode" yaml:"user_mode"`

	// PK is the Platform Key database summary.
	PK SignatureDatabase `json:"pk" yaml:"pk"`

	// KEK is the Key Exchange Key database summary.
	KEK SignatureDatabase `json:"kek" yaml:"kek"`

	// DB is the authorized signature database summary.
	DB SignatureDatabase `json:"db" yaml:"db"`

	// DBX is the forbidden signature database summary.
	DBX SignatureDatabase `json:"dbx" yaml:"dbx"`
}

// ReadSecureBootStatus reads the firmware Secure Boot state from the standard
// efivarfs mount point. It returns ErrEfivarsUnavailable when efivarfs is not
// mounted (BIOS/CSM boot, or a container without /sys passthrough).
func ReadSecureBootStatus() (*SecureBootStatus, error) {
	return ReadSecureBootStatusFromDir(EfivarsPath)
}

// ReadSecureBootStatusFromDir reads the firmware Secure Boot state from an
// efivarfs-layout directory. It is the read counterpart to EnrollKeysToEfivarsDir
// and exists so the parse logic can be exercised against a fixture directory
// without a UEFI host.
func ReadSecureBootStatusFromDir(dir string) (*SecureBootStatus, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, ErrEfivarsUnavailable
	}

	status := &SecureBootStatus{EfivarsAvailable: true}

	setup, err := readEfivarBoolFile(filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable)))
	if err != nil {
		return nil, &ErrEfivarRead{Var: "SetupMode", Cause: err}
	}
	status.SetupMode = setup

	sb, err := readEfivarBoolFile(filepath.Join(dir, efivarFileName("SecureBoot", EFIGlobalVariable)))
	if err != nil {
		return nil, &ErrEfivarRead{Var: "SecureBoot", Cause: err}
	}
	status.SecureBoot = sb

	databases := []struct {
		name   string
		vendor GUID
		dest   *SignatureDatabase
	}{
		{"PK", EFIGlobalVariable, &status.PK},
		{"KEK", EFIGlobalVariable, &status.KEK},
		{"db", EFIImageSecurityDatabase, &status.DB},
		{"dbx", EFIImageSecurityDatabase, &status.DBX},
	}
	for _, d := range databases {
		summary, err := readSignatureDatabaseFile(
			filepath.Join(dir, efivarFileName(d.name, d.vendor)), d.name)
		if err != nil {
			return nil, err
		}
		*d.dest = *summary
	}

	status.UserMode = !status.SetupMode && status.PK.Present
	return status, nil
}

// readSignatureDatabaseFile reads one signature database variable file and
// summarizes its EFI_SIGNATURE_LIST contents. A missing file yields a
// non-Present summary rather than an error; malformed content is an error.
func readSignatureDatabaseFile(path, name string) (*SignatureDatabase, error) {
	summary := &SignatureDatabase{Name: name}

	present, lists, err := readSignatureLists(path, name)
	if err != nil {
		return nil, err
	}
	summary.Present = present
	for _, list := range lists {
		switch {
		case list.IsX509():
			for _, sig := range list.Signatures {
				summary.Certificates++
				if cert, certErr := x509.ParseCertificate(sig.Data); certErr == nil {
					summary.Subjects = append(summary.Subjects, cert.Subject.String())
				} else {
					// The entry is a real X.509 signature list member the
					// firmware will honor even though Go cannot parse it;
					// report it honestly instead of dropping it.
					summary.Subjects = append(summary.Subjects, "<unparseable X.509 certificate>")
				}
			}
		case list.IsSHA256():
			summary.Hashes += len(list.Signatures)
		default:
			summary.Other += len(list.Signatures)
		}
	}
	return summary, nil
}

// readSignatureLists reads one signature database variable file and parses
// its EFI_SIGNATURE_LIST contents. A missing file is not present and holds no
// lists; malformed content is an error.
func readSignatureLists(path, name string) (bool, []*SignatureList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, &ErrEfivarRead{Var: name, Cause: err}
	}

	// efivarfs prepends a 4-byte little-endian attribute word.
	if len(data) < 4 {
		return false, nil, &ErrEfivarRead{Var: name, Cause: ErrInvalidFormat}
	}

	payload := data[4:]
	if len(payload) == 0 {
		// Present but empty (possible after a variable delete-write race).
		return true, nil, nil
	}

	// A real efivarfs read returns only the stored EFI_SIGNATURE_LIST data —
	// the firmware consumes the EFI_VARIABLE_AUTHENTICATION_2 descriptor at
	// SetVariable time. Fixture directories written by EnrollKeysToEfivarsDir
	// (CLI dry-run rehearsal, unit tests) still carry that descriptor, so it
	// is detected structurally and skipped before ESL parsing.
	if rest, ok := skipAuthDescriptor(payload); ok {
		payload = rest
	}

	lists, err := ParseSignatureLists(payload)
	if err != nil {
		return false, nil, &ErrEfivarRead{Var: name, Cause: err}
	}
	return true, lists, nil
}

// ReadDBCertificates returns the X.509 certificates enrolled in the firmware's
// authorized signature database (db), read from the standard efivarfs mount
// point. See ReadDBCertificatesFromDir.
func ReadDBCertificates() ([]*x509.Certificate, error) {
	return ReadDBCertificatesFromDir(EfivarsPath)
}

// ReadDBCertificatesFromDir returns the X.509 certificates in the db variable
// of an efivarfs-layout directory: the certificates the firmware accepts boot
// code from. It returns ErrEfivarsUnavailable without the directory and no
// certificates without a db. Hash entries, and certificate entries Go cannot
// parse, are not returned: neither can verify a signature.
func ReadDBCertificatesFromDir(dir string) ([]*x509.Certificate, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, ErrEfivarsUnavailable
	}
	_, lists, err := readSignatureLists(filepath.Join(dir, efivarFileName("db", EFIImageSecurityDatabase)), "db")
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, list := range lists {
		if !list.IsX509() {
			continue
		}
		for _, sig := range list.Signatures {
			if cert, certErr := x509.ParseCertificate(sig.Data); certErr == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

// skipAuthDescriptor structurally detects an EFI_VARIABLE_AUTHENTICATION_2
// descriptor (EFI_TIME + WIN_CERTIFICATE_UEFI_GUID with the PKCS#7 cert type
// GUID) at the start of data and returns the bytes that follow it. It reports
// false when the data does not begin with a well-formed descriptor, in which
// case the data is treated as raw EFI_SIGNATURE_LIST content.
func skipAuthDescriptor(data []byte) ([]byte, bool) {
	const descriptorFixed = EFITimeSize + winCertHeaderSize + GUIDSize // 16 + 8 + 16
	if len(data) < descriptorFixed {
		return nil, false
	}
	dwLength := binary.LittleEndian.Uint32(data[EFITimeSize : EFITimeSize+4])
	revision := binary.LittleEndian.Uint16(data[EFITimeSize+4 : EFITimeSize+6])
	certType := binary.LittleEndian.Uint16(data[EFITimeSize+6 : EFITimeSize+8])
	if revision != winCertRevision || certType != winCertTypeEFIGUID {
		return nil, false
	}
	guid, err := GUIDFromBytes(data[EFITimeSize+winCertHeaderSize : descriptorFixed])
	if err != nil || guid != EFIPKCS7Cert {
		return nil, false
	}
	// dwLength covers the WIN_CERTIFICATE header, the cert-type GUID, and the
	// PKCS#7 CertData; the descriptor as a whole is EFI_TIME + dwLength bytes.
	total := EFITimeSize + int(dwLength)
	if dwLength < winCertHeaderSize+GUIDSize || total > len(data) {
		return nil, false
	}
	return data[total:], true
}
