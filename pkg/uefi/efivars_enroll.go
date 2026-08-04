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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// EfivarsPath is the standard efivarfs mount point on Linux. It is a package
// variable rather than a constant so tests can redirect the bare-metal reads
// and writes at a temporary directory without touching the real firmware.
var EfivarsPath = "/sys/firmware/efi/efivars"

// WIN_CERTIFICATE / EFI_VARIABLE_AUTHENTICATION_2 constants (UEFI spec §32.2.4,
// §8.2.2). They describe the authenticated-variable descriptor that prefixes the
// EFI_SIGNATURE_LIST payload of a time-based authenticated write.
const (
	// winCertRevision is WIN_CERTIFICATE.wRevision for the 2.0 format.
	winCertRevision uint16 = 0x0200

	// winCertTypeEFIGUID is WIN_CERTIFICATE.wCertificateType =
	// WIN_CERT_TYPE_EFI_GUID, selecting the WIN_CERTIFICATE_UEFI_GUID layout.
	winCertTypeEFIGUID uint16 = 0x0EF1

	// winCertHeaderSize is sizeof(WIN_CERTIFICATE): dwLength(4) + wRevision(2)
	// + wCertificateType(2).
	winCertHeaderSize = 8

	// fsImmutableFlag is FS_IMMUTABLE_FL from <linux/fs.h>. efivarfs marks
	// already-set variables immutable; x/sys/unix does not export the flag.
	fsImmutableFlag = 0x00000010
)

// secureBootKeyOwnerGUID identifies go-trusted-platform as the owner of each
// enrolled Secure Boot certificate inside its EFI_SIGNATURE_LIST. The owner
// GUID is informational only — firmware acceptance of a signed image depends on
// the certificate, not on the owner GUID.
var secureBootKeyOwnerGUID = TrustedPlatformGUID

// Typed errors for the bare-metal enrollment + verify path. Sentinel values are
// used for the parameterless conditions; ErrEnrollWrite and ErrUKIVerify carry
// the failing variable / underlying cause.
var (
	// ErrNotSetupMode indicates the firmware is not in Setup Mode, so raw key
	// enrollment is not permitted (the operator must clear Secure Boot keys in
	// firmware setup first).
	ErrNotSetupMode = errors.New("uefi: firmware not in setup mode")

	// ErrEfivarsUnavailable indicates the efivarfs pseudo-filesystem is not
	// mounted, so EFI variables can be neither read nor written.
	ErrEfivarsUnavailable = errors.New("uefi: efivarfs not available")

	errNilEnrollCert   = errors.New("uefi: certificate is nil")
	errNilVerifier     = errors.New("uefi: uki verifier is nil")
	errUKICertMismatch = errors.New("uefi: signed uki certificate does not match db certificate")
)

// ErrEnrollWrite reports a failure writing a Secure Boot variable (db, KEK, or
// PK) into efivarfs.
type ErrEnrollWrite struct {
	Var   string
	Cause error
}

func (e *ErrEnrollWrite) Error() string {
	return "uefi: failed to write secure boot variable " + e.Var + ": " + e.Cause.Error()
}

func (e *ErrEnrollWrite) Unwrap() error { return e.Cause }

// ErrUKIVerify reports that the signed UKI failed verify-before-enforce: either
// its Authenticode signature is invalid or its signing certificate does not
// match the db certificate about to be enrolled.
type ErrUKIVerify struct {
	Cause error
}

func (e *ErrUKIVerify) Error() string {
	return "uefi: signed uki verification failed: " + e.Cause.Error()
}

func (e *ErrUKIVerify) Unwrap() error { return e.Cause }

// NewEFITime converts a Go time to an EFI_TIME suitable for an
// EFI_VARIABLE_AUTHENTICATION_2 timestamp. Per the UEFI spec the Pad1,
// Nanosecond, TimeZone, Daylight and Pad2 components must be zero and the time
// must be in GMT, so the input is normalised to UTC and those fields left zero.
func NewEFITime(t time.Time) EFITime {
	u := t.UTC()
	return EFITime{
		Year:   uint16(u.Year()),
		Month:  uint8(u.Month()),
		Day:    uint8(u.Day()),
		Hour:   uint8(u.Hour()),
		Minute: uint8(u.Minute()),
		Second: uint8(u.Second()),
	}
}

// Bytes marshals the EFI_TIME structure to its 16-byte on-the-wire form. All
// multi-byte fields are little-endian, matching the UEFI EFI_TIME layout.
func (t EFITime) Bytes() []byte {
	b := make([]byte, EFITimeSize)
	binary.LittleEndian.PutUint16(b[0:2], t.Year)
	b[2] = t.Month
	b[3] = t.Day
	b[4] = t.Hour
	b[5] = t.Minute
	b[6] = t.Second
	b[7] = t.Pad1
	binary.LittleEndian.PutUint32(b[8:12], t.Nanosecond)
	binary.LittleEndian.PutUint16(b[12:14], uint16(t.TimeZone))
	b[14] = t.Daylight
	b[15] = t.Pad2
	return b
}

// marshalAuthDescriptor builds the EFI_VARIABLE_AUTHENTICATION_2 descriptor for
// a Setup-Mode raw enroll:
//
//	EFI_TIME                  TimeStamp;   // 16 bytes
//	WIN_CERTIFICATE_UEFI_GUID AuthInfo;    // header + EFI_CERT_TYPE_PKCS7_GUID
//
// In Setup Mode the firmware does not require the write to chain to an existing
// PK, so the WIN_CERTIFICATE_UEFI_GUID carries an EMPTY signature payload
// (CertData). dwLength therefore covers only the 8-byte WIN_CERTIFICATE header
// plus the 16-byte EFI_GUID.
func marshalAuthDescriptor(ts EFITime) []byte {
	buf := new(bytes.Buffer)
	buf.Write(ts.Bytes()) // EFI_TIME (16)

	dwLength := uint32(winCertHeaderSize + GUIDSize) // 8 + 16, no CertData
	_ = binary.Write(buf, binary.LittleEndian, dwLength)
	_ = binary.Write(buf, binary.LittleEndian, winCertRevision)
	_ = binary.Write(buf, binary.LittleEndian, winCertTypeEFIGUID)
	buf.Write(EFIPKCS7Cert.Bytes()) // EFI_CERT_TYPE_PKCS7_GUID (16)
	// CertData is intentionally empty for a Setup-Mode enroll.
	return buf.Bytes()
}

// encodeEfivarsAuthPayload builds the exact byte content written to an efivarfs
// file for a time-based authenticated variable:
//
//	<uint32 attributes LE> || EFI_VARIABLE_AUTHENTICATION_2 || EFI_SIGNATURE_LIST
//
// efivarfs strips the leading 4-byte attribute word and forwards the remainder
// to SetVariable.
func encodeEfivarsAuthPayload(attrs uint32, ts EFITime, esl []byte) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, attrs)
	buf.Write(marshalAuthDescriptor(ts))
	buf.Write(esl)
	return buf.Bytes()
}

// efivarFileName returns the efivarfs filename for a variable: the variable
// name, a hyphen, and the lowercase vendor GUID string (e.g.
// "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f").
func efivarFileName(name string, vendorGUID GUID) string {
	return name + "-" + strings.ToLower(vendorGUID.String())
}

// parseEfivarBool interprets the raw content of an efivarfs file that holds a
// single-byte boolean variable (SetupMode, SecureBoot). efivarfs prepends a
// 4-byte little-endian attribute word to the variable data, so the value byte
// is at offset 4. It reports true when that byte is 0x01.
func parseEfivarBool(data []byte) (bool, error) {
	if len(data) < 5 {
		return false, ErrInvalidFormat
	}
	return data[4] == 0x01, nil
}

// readEfivarBoolFile reads a 1-byte boolean efivar from path. A missing file
// (efivarfs or the variable absent) yields (false, nil) so callers treat the
// firmware feature as simply not set rather than as an error.
func readEfivarBoolFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return parseEfivarBool(data)
}

// readEfivarBool reads a global-namespace boolean variable from efivarfs.
func readEfivarBool(varName string) (bool, error) {
	path := filepath.Join(EfivarsPath, efivarFileName(varName, EFIGlobalVariable))
	return readEfivarBoolFile(path)
}

// EfivarsAvailable reports whether the efivarfs pseudo-filesystem is mounted.
func EfivarsAvailable() bool {
	info, err := os.Stat(EfivarsPath)
	return err == nil && info.IsDir()
}

// IsSetupMode reports whether the firmware is in Secure Boot Setup Mode, in
// which raw (unauthenticated) key enrollment is permitted. It returns false if
// efivarfs or the SetupMode variable is absent.
func IsSetupMode() (bool, error) {
	return readEfivarBool("SetupMode")
}

// SecureBootEnabled reports whether the firmware currently has Secure Boot
// enforced. It returns false if efivarfs or the SecureBoot variable is absent.
func SecureBootEnabled() (bool, error) {
	return readEfivarBool("SecureBoot")
}

// EnrollKeysToEfivars enrolls the Secure Boot certificates into the running
// firmware via efivarfs in the safe order db -> KEK -> PK (PK LAST). The
// firmware leaves Setup Mode — and Secure Boot becomes enforced — only when PK
// is set, so any failure before PK leaves the node booting unsigned rather than
// locked to keys it cannot satisfy.
//
// It refuses to write unless efivarfs is mounted (ErrEfivarsUnavailable) and the
// firmware is in Setup Mode (ErrNotSetupMode); these guards make a stray call a
// no-op rather than a partial enrollment.
func EnrollKeysToEfivars(ctx context.Context, pkCert, kekCert, dbCert *x509.Certificate, ts EFITime) error {
	return EnrollKeysToEfivarsDir(ctx, EfivarsPath, pkCert, kekCert, dbCert, ts)
}

// EnrollKeysToEfivarsDir enrolls the Secure Boot certificates into an
// efivarfs-layout directory with the same guards as EnrollKeysToEfivars:
// the directory must exist (ErrEfivarsUnavailable) and its SetupMode variable
// must report Setup Mode (ErrNotSetupMode). It exists so the guarded write
// path can be exercised against a fixture directory and so callers with a
// non-standard efivarfs mount can enroll safely.
func EnrollKeysToEfivarsDir(ctx context.Context, dir string, pkCert, kekCert, dbCert *x509.Certificate, ts EFITime) error {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ErrEfivarsUnavailable
	}
	setup, err := readEfivarBoolFile(filepath.Join(dir, efivarFileName("SetupMode", EFIGlobalVariable)))
	if err != nil {
		return &ErrEfivarRead{Var: "SetupMode", Cause: err}
	}
	if !setup {
		return ErrNotSetupMode
	}
	return enrollKeysToDir(ctx, dir, pkCert, kekCert, dbCert, ts, logging.DefaultLogger())
}

// enrollKeysToDir writes the db, KEK and PK authenticated variables into baseDir
// in the safe order. It is factored out of EnrollKeysToEfivars so the
// byte-exact write + ordering can be exercised against a temporary directory
// without touching the real /sys/firmware/efi.
func enrollKeysToDir(ctx context.Context, baseDir string, pkCert, kekCert, dbCert *x509.Certificate, ts EFITime, logger *logging.Logger) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// db FIRST — defines which signing certificates the firmware will accept.
	if err := writeKeyVarToDir(baseDir, "db", EFIImageSecurityDatabase, dbCert, ts); err != nil {
		return err
	}
	logger.Debug("[SECUREBOOT] enrolled db certificate via efivars")

	// KEK next.
	if err := writeKeyVarToDir(baseDir, "KEK", EFIGlobalVariable, kekCert, ts); err != nil {
		return err
	}
	logger.Debug("[SECUREBOOT] enrolled KEK certificate via efivars")

	// PK LAST — writing PK is the step that takes the firmware out of Setup
	// Mode and activates enforced Secure Boot.
	if err := writeKeyVarToDir(baseDir, "PK", EFIGlobalVariable, pkCert, ts); err != nil {
		return err
	}
	logger.Debug("[SECUREBOOT] enrolled PK certificate via efivars (Secure Boot now enforced)")
	return nil
}

// writeKeyVarToDir serialises one Secure Boot certificate as an
// EFI_SIGNATURE_LIST wrapped in a time-based authenticated variable and writes
// it to baseDir/<name>-<vendor-guid>.
func writeKeyVarToDir(baseDir, name string, vendorGUID GUID, cert *x509.Certificate, ts EFITime) error {
	if cert == nil {
		return &ErrEnrollWrite{Var: name, Cause: errNilEnrollCert}
	}
	esl := NewSignatureListFromCert(cert.Raw, secureBootKeyOwnerGUID).Bytes()
	payload := encodeEfivarsAuthPayload(SecureBootAttributes, ts, esl)
	path := filepath.Join(baseDir, efivarFileName(name, vendorGUID))
	return writeAuthenticatedVarFile(path, payload)
}

// writeAuthenticatedVarFile writes payload to an efivarfs variable file. If the
// file already exists efivarfs marks it immutable; the immutable flag is cleared
// and the write retried once before failing.
func writeAuthenticatedVarFile(path string, payload []byte) error {
	varName := filepath.Base(path)
	if err := os.WriteFile(path, payload, 0644); err != nil {
		if clearErr := clearImmutable(path); clearErr == nil {
			if retryErr := os.WriteFile(path, payload, 0644); retryErr != nil {
				return &ErrEnrollWrite{Var: varName, Cause: retryErr}
			}
			return nil
		}
		return &ErrEnrollWrite{Var: varName, Cause: err}
	}
	return nil
}

// clearImmutable clears the FS_IMMUTABLE_FL flag on path so an existing efivarfs
// variable can be rewritten.
func clearImmutable(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	flags &^= fsImmutableFlag
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, flags)
}

// UKIVerifier verifies an Authenticode signature on a UKI and extracts the
// embedded signing certificate. It is satisfied by *authenticode.Signer, which
// the installer builds from the resolved Secure Boot DB key. Accepting the
// interface here keeps pkg/uefi free of any keystore / SDK dependency.
type UKIVerifier interface {
	// VerifyFile verifies the Authenticode signature on the file at path.
	VerifyFile(path string) error
	// ExtractCertificateFile returns the signing certificate embedded in the
	// signed file at path.
	ExtractCertificateFile(path string) (*x509.Certificate, error)
}

// VerifySignedUKI is the verify-before-enforce brick guard. It confirms the
// signed UKI at ukiPath carries a valid Authenticode signature AND that its
// signing certificate is exactly dbCert — the certificate that will be enrolled
// into the Secure Boot db. Only when both hold will firmware with this db accept
// the UKI, so passing this gate means enrolling PK (and thereby enforcing Secure
// Boot) cannot strand the node on an image it will refuse to boot.
func VerifySignedUKI(verifier UKIVerifier, ukiPath string, dbCert *x509.Certificate, logger *logging.Logger) error {
	if verifier == nil {
		return &ErrUKIVerify{Cause: errNilVerifier}
	}
	if dbCert == nil {
		return &ErrUKIVerify{Cause: errNilEnrollCert}
	}
	if err := verifier.VerifyFile(ukiPath); err != nil {
		return &ErrUKIVerify{Cause: err}
	}
	embedded, err := verifier.ExtractCertificateFile(ukiPath)
	if err != nil {
		return &ErrUKIVerify{Cause: err}
	}
	if embedded == nil || !bytes.Equal(embedded.Raw, dbCert.Raw) {
		return &ErrUKIVerify{Cause: errUKICertMismatch}
	}
	if logger != nil {
		logger.Info("[SECUREBOOT] signed UKI verified against db certificate", "uki", ukiPath)
	}
	return nil
}
