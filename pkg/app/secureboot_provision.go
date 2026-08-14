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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// Package app / secureboot_provision.go provisions the Secure Boot PK, KEK and
// DB key material during platformd firstboot.
//
// The platform config references Secure Boot keys through kms:// URIs, e.g.
//
//	secure-boot:
//	  pk:  { cn: "...", store: tpm2,     key-uri: kms://platform/secureboot/pk,  cert-uri: kms://platform/secureboot/pk-cert }
//	  kek: { cn: "...", store: tpm2,     key-uri: kms://platform/secureboot/kek, cert-uri: kms://platform/secureboot/kek-cert }
//	  db:  { cn: "...", store: software, key-uri: kms://platform/secureboot/db,  cert-uri: kms://platform/secureboot/db-cert }
//
// Those URIs carry no ?ensure=true because the material is a keypair plus an
// X.509 certificate, not a random secret — the generate-on-first-use path in
// the LocalKMS resolver would mint random bytes and corrupt the Secure Boot
// chain. Instead this provisioner runs BEFORE App.ProcessSecrets so the
// subsequent fail-closed config walk finds real material at every path.
//
// The provisioner is idempotent: an entry whose private key already exists in
// the KMS is skipped untouched. Overwriting a DB key would invalidate every
// UKI and kernel module already signed with it, so the existence check fails
// closed on any KMS error it cannot positively identify as "not found".
//
// TODO(secure-boot): PK and KEK are configured with `store: tpm2`. This
// provisioner software-generates them and escrows the PEM in the KMS.
// TPM-resident PK/KEK creation (primary key under the owner hierarchy with a
// non-exportable private area, certified by the platform CA) is a follow-up —
// it requires the xkms TPM2 backend to be online before secret resolution,
// which is not the case at this point in App.Init.

// Secure Boot provisioning defaults. RSA-2048 is the interoperable choice for
// UEFI: ECDSA db entries are rejected by a number of shipping firmwares.
const (
	secureBootDefaultRSABits    = 2048
	secureBootDefaultValidYears = 10
	secureBootKMSScheme         = "kms://"
	secureBootProvisionSource   = "firstboot-secureboot-provision"
	secureBootPEMContentType    = "application/x-pem-file"
)

// secureBootRole identifies which of the three UEFI Secure Boot key slots an
// entry provisions.
type secureBootRole string

const (
	secureBootRolePK  secureBootRole = "pk"
	secureBootRoleKEK secureBootRole = "kek"
	secureBootRoleDB  secureBootRole = "db"
)

// secureBootDefaultCN maps a role to the Subject CN used when the config omits
// one, so provisioning never mints a certificate with an empty Subject.
var secureBootDefaultCN = map[secureBootRole]string{
	secureBootRolePK:  "Trusted Platform Secure Boot PK",
	secureBootRoleKEK: "Trusted Platform Secure Boot KEK",
	secureBootRoleDB:  "Trusted Platform Secure Boot DB",
}

// secretStore is the minimal SecretsService surface the Secure Boot
// provisioner needs. baasservice.SecretsService satisfies it; narrowing the
// dependency keeps the provisioner unit-testable without a live QuicBaaS.
type secretStore interface {
	GetSecret(ctx context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error)
	StoreSecret(ctx context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error)
}

// ErrSecureBootProvision reports a Secure Boot provisioning failure for a
// single key slot.
type ErrSecureBootProvision struct {
	Role  secureBootRole
	Stage string
	Cause error
}

// Error implements the error interface.
func (e *ErrSecureBootProvision) Error() string {
	msg := "secureboot-provision: " + string(e.Role) + ": " + e.Stage
	if e.Cause != nil {
		return msg + ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause.
func (e *ErrSecureBootProvision) Unwrap() error { return e.Cause }

// ErrSecureBootSecretsUnavailable is returned when Secure Boot key material
// must be provisioned but the KMS-backed SecretsService is not reachable.
type ErrSecureBootSecretsUnavailable struct{}

// Error implements the error interface.
func (e *ErrSecureBootSecretsUnavailable) Error() string {
	return "secureboot-provision: SecretsService not available; cannot provision Secure Boot PK/KEK/DB key material"
}

// ErrSecureBootExistenceCheck is returned when the KMS answers the "does this
// key already exist?" probe with an error that is not a clean not-found. The
// provisioner fails closed rather than risk overwriting live Secure Boot keys.
type ErrSecureBootExistenceCheck struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *ErrSecureBootExistenceCheck) Error() string {
	return "secureboot-provision: indeterminate KMS response for " + e.Path +
		"; refusing to overwrite potentially live Secure Boot key material: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrSecureBootExistenceCheck) Unwrap() error { return e.Cause }

// secureBootEntry pairs a Secure Boot slot with its configured key reference.
type secureBootEntry struct {
	role secureBootRole
	ref  *installer.SecureBootKeyRef
}

// secureBootEntries returns the PK, KEK and DB entries in provisioning order.
func secureBootEntries(cfg *installer.SecureBootConfig) []secureBootEntry {
	return []secureBootEntry{
		{secureBootRolePK, &cfg.PK},
		{secureBootRoleKEK, &cfg.KEK},
		{secureBootRoleDB, &cfg.DB},
	}
}

// ProvisionSecureBootKeys generates and stores the Secure Boot PK, KEK and DB
// keypairs plus their self-signed certificates in the KMS so the kms:// URIs
// in the secure-boot config resolve on first boot.
//
// It must run after initStores (SecretsService online) and before
// ProcessSecrets (fail-closed config walk). It is a no-op when Secure Boot is
// not configured or not enabled, and idempotent for entries already present.
func (app *App) ProvisionSecureBootKeys(ctx context.Context) error {
	cfg := app.SecureBootConfig
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	// A config whose entries are all file:// (airgap provisioning) needs no
	// KMS at all, so don't demand a SecretsService for it.
	needsKMS := false
	for _, entry := range secureBootEntries(cfg) {
		if _, ok := secureBootKMSPath(entry.ref.KeyURI); ok {
			needsKMS = true
			break
		}
	}
	if !needsKMS {
		app.Logger.Debug("secureboot-provision: no kms:// key-uri configured, nothing to provision")
		return nil
	}

	store := app.secureBootSecretStore()
	if store == nil {
		return &ErrSecureBootSecretsUnavailable{}
	}
	return app.provisionSecureBootKeys(ctx, store)
}

// provisionSecureBootKeys walks the configured Secure Boot slots against an
// explicit secret store. Split from ProvisionSecureBootKeys so the generation
// and idempotence behavior is exercisable without a live QuicBaaS.
func (app *App) provisionSecureBootKeys(ctx context.Context, store secretStore) error {
	for _, entry := range secureBootEntries(app.SecureBootConfig) {
		keyPath, ok := secureBootKMSPath(entry.ref.KeyURI)
		if !ok {
			app.Logger.Debug("secureboot-provision: skipping entry without a kms:// key-uri",
				"role", string(entry.role), "key_uri", entry.ref.KeyURI)
			continue
		}
		certPath, ok := secureBootKMSPath(entry.ref.CertURI)
		if !ok {
			return &ErrSecureBootProvision{
				Role:  entry.role,
				Stage: "resolve cert-uri",
				Cause: &MessageError{Msg: "key-uri is kms:// but cert-uri is not; both must be KMS-managed"},
			}
		}
		if err := app.provisionSecureBootEntry(ctx, store, entry.role, entry.ref, keyPath, certPath); err != nil {
			return err
		}
	}
	return nil
}

// secureBootSecretStore returns the KMS-backed secret store, or nil when the
// SecretsService is not available. Split out so the typed-nil interface trap
// (a nil baasservice.SecretsService boxed into secretStore) cannot occur.
func (app *App) secureBootSecretStore() secretStore {
	svc := app.Secrets()
	if svc == nil {
		return nil
	}
	return svc
}

// provisionSecureBootEntry provisions one Secure Boot slot. It returns nil
// without touching the KMS when the private key is already present.
func (app *App) provisionSecureBootEntry(
	ctx context.Context,
	store secretStore,
	role secureBootRole,
	ref *installer.SecureBootKeyRef,
	keyPath, certPath string,
) error {
	exists, err := secureBootSecretExists(ctx, store, keyPath)
	if err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "probe existing key", Cause: err}
	}
	if exists {
		app.Logger.Info("secureboot-provision: key already present, leaving untouched",
			"role", string(role), "key_path", keyPath)
		return nil
	}

	cn := ref.CN
	if cn == "" {
		cn = secureBootDefaultCN[role]
	}

	key, algorithm, err := generateSecureBootKey(ref)
	if err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "generate key", Cause: err}
	}

	certDER, err := selfSignSecureBootCertificate(role, cn, key)
	if err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "self-sign certificate", Cause: err}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "marshal private key", Cause: err}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	createdAt := time.Now().UTC().Format(time.RFC3339)
	baseMeta := func(kind string) map[string]string {
		return map[string]string{
			"source":       secureBootProvisionSource,
			"category":     "secure-boot",
			"role":         string(role),
			"kind":         kind,
			"cn":           cn,
			"algorithm":    algorithm,
			"store":        ref.StoreType,
			"created_at":   createdAt,
			"content_type": secureBootPEMContentType,
		}
	}

	// Store the certificate first: a crash between the two writes then leaves
	// a certificate without a key, which the next boot re-provisions cleanly
	// (the key probe is the idempotence anchor). The reverse order would
	// strand a key whose certificate never lands.
	if _, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name:        certPath,
		Description: "Secure Boot " + strings.ToUpper(string(role)) + " certificate",
		Data:        certPEM,
		Metadata:    baseMeta("certificate"),
	}); err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "store certificate at " + certPath, Cause: err}
	}

	if _, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name:        keyPath,
		Description: "Secure Boot " + strings.ToUpper(string(role)) + " private key",
		Data:        keyPEM,
		Metadata:    baseMeta("private-key"),
	}); err != nil {
		return &ErrSecureBootProvision{Role: role, Stage: "store private key at " + keyPath, Cause: err}
	}

	app.Logger.Info("secureboot-provision: generated Secure Boot key material",
		"role", string(role),
		"cn", cn,
		"algorithm", algorithm,
		"key_path", keyPath,
		"cert_path", certPath,
	)
	return nil
}

// secureBootKMSPath strips the kms:// scheme and any query string from uri,
// yielding the secret ID the LocalKMS resolver will later look up. The second
// return value is false when uri is empty or uses a different scheme (file://
// airgap provisioning is the operator's responsibility, not ours).
func secureBootKMSPath(uri string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(uri), secureBootKMSScheme) {
		return "", false
	}
	path := uri[len(secureBootKMSScheme):]
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if idx := strings.IndexByte(path, '#'); idx >= 0 {
		path = path[:idx]
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return "", false
	}
	return path, true
}

// secureBootSecretExists reports whether a secret holding data is present at
// path. A clean not-found answers false; any other error is returned so the
// caller fails closed instead of overwriting live key material.
func secureBootSecretExists(ctx context.Context, store secretStore, path string) (bool, error) {
	resp, err := store.GetSecret(ctx, &baasservice.GetSecretRequest{SecretID: path})
	if err == nil {
		return resp != nil && len(resp.Data) > 0, nil
	}
	if isSecureBootSecretNotFound(err) {
		return false, nil
	}
	return false, &ErrSecureBootExistenceCheck{Path: path, Cause: err}
}

// isSecureBootSecretNotFound reports whether err means "no such secret". The
// KMS surfaces not-found through several concrete types depending on which
// transport served the call, so the typed checks are backed by a message
// probe of last resort.
func isSecureBootSecretNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound *quicbaassecret.SecretNotFoundError
	if errors.As(err, &notFound) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// generateSecureBootKey generates a keypair for one Secure Boot slot honoring
// the algorithm hints in the entry's KeyConfig. It returns the key and a
// human-readable algorithm label for the secret metadata.
func generateSecureBootKey(ref *installer.SecureBootKeyRef) (crypto.PrivateKey, string, error) {
	switch strings.ToUpper(strings.TrimSpace(ref.KeyAlgorithm)) {
	case "ECDSA":
		curve, label, err := secureBootCurve(ref)
		if err != nil {
			return nil, "", err
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, "", err
		}
		return key, label, nil

	case "", "RSA":
		bits := secureBootDefaultRSABits
		if ref.RSAConfig != nil && ref.RSAConfig.KeySize > 0 {
			bits = ref.RSAConfig.KeySize
		}
		if bits < secureBootDefaultRSABits {
			return nil, "", &MessageError{Msg: "secure boot RSA key size must be at least 2048 bits"}
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, "", err
		}
		return key, "RSA-" + strconv.Itoa(bits), nil

	default:
		return nil, "", &MessageError{Msg: "unsupported secure boot key algorithm: " + ref.KeyAlgorithm}
	}
}

// secureBootCurve resolves the configured ECC curve, defaulting to P-256.
func secureBootCurve(ref *installer.SecureBootKeyRef) (elliptic.Curve, string, error) {
	name := "P-256"
	if ref.ECCConfig != nil && ref.ECCConfig.Curve != "" {
		name = strings.ToUpper(strings.TrimSpace(ref.ECCConfig.Curve))
	}
	switch name {
	case "P-256", "P256", "SECP256R1", "PRIME256V1":
		return elliptic.P256(), "ECDSA-P256", nil
	case "P-384", "P384", "SECP384R1":
		return elliptic.P384(), "ECDSA-P384", nil
	case "P-521", "P521", "SECP521R1":
		return elliptic.P521(), "ECDSA-P521", nil
	default:
		return nil, "", &MessageError{Msg: "unsupported secure boot ECC curve: " + name}
	}
}

// selfSignSecureBootCertificate issues the self-signed X.509 certificate that
// accompanies a Secure Boot keypair. PK, KEK and DB are all self-signed CA
// certificates: firmware enrolls the DER form into the corresponding UEFI
// signature database, and sbsign consumes the DB pair to sign the UKI.
func selfSignSecureBootCertificate(role secureBootRole, cn string, key crypto.PrivateKey) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &MessageError{Msg: "secure boot key does not implement crypto.Signer"}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Trusted Platform"},
			Country:      []string{"US"},
		},
		// Backdate to absorb clock skew on nodes whose RTC has not yet been
		// disciplined by NTP at firstboot.
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(secureBootDefaultValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if role == secureBootRoleDB {
		// The DB key is the one that actually signs PE/COFF images.
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	return x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
}
