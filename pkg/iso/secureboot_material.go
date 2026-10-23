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

package iso

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// SecureBootCertDirName is the directory under the build's work directory
// that holds the resolved PK, KEK and DB certificates.
const SecureBootCertDirName = "secure-boot-certs"

// KMSClients are the operator's platform clients a build reaches kms://
// Secure Boot references through: platform.Client's KMS() and CA().
type KMSClients struct {
	KMS secureboot.KMSSignClient
	CA  secureboot.CertificateGetter
}

// KMSClientsFunc opens the operator's platform clients. A build calls it only
// when the platform config names a kms:// reference, so a build that signs
// with file keys never connects.
type KMSClientsFunc func() (*KMSClients, error)

// SecureBootMaterial is what a build preseeds and signs with.
type SecureBootMaterial struct {
	// CertDir holds PK.crt, KEK.crt and DB.crt (PEM): the certificates the
	// U-Boot preseed and the media's enrollment set are built from.
	CertDir string
	// DB signs build artifacts (kernels, iPXE) with the Secure Boot DB key:
	// the KMS-held key for a kms:// reference, the file pair otherwise.
	DB authenticode.Authenticode
	// DBKey and DBCert are the same DB key and its certificate, for signing
	// what is not a PE image: the diskless root manifest, which the
	// installer verifies against the DB certificate on its media.
	DBKey  crypto.Signer
	DBCert *x509.Certificate
}

// ResolveSecureBootMaterial resolves the build's Secure Boot certificates and
// DB signer from the platform config's secure-boot section, whatever holds the
// keys: a kms:// reference is fetched through the operator's platform client
// (the private key never leaves the KMS), a media file:// reference or no
// reference is read from build.KeysDir. It returns nil when Secure Boot is off.
func ResolveSecureBootMaterial(ctx context.Context, build *ISOBuildConfig, clients KMSClientsFunc, logger *logging.Logger) (*SecureBootMaterial, error) {
	if !build.SecureBoot {
		return nil, nil
	}
	sb, err := platformSecureBoot(build.PlatformConfigFile)
	if err != nil {
		return nil, err
	}
	r := &materialResolver{build: build, sb: sb, clientsFunc: clients}

	certDir := filepath.Join(build.WorkDir, SecureBootCertDirName)
	if err := os.RemoveAll(certDir); err != nil {
		return nil, &SecureBootMaterialError{Step: "clearing " + certDir, Err: err}
	}
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, &SecureBootMaterialError{Step: "creating " + certDir, Err: err}
	}
	for _, role := range []struct {
		name string
		ref  installer.SecureBootKeyRef
	}{{"PK", sb.PK}, {"KEK", sb.KEK}, {"DB", sb.DB}} {
		cert, err := r.certificate(ctx, role.name, role.ref)
		if err != nil {
			return nil, err
		}
		out := filepath.Join(certDir, role.name+".crt")
		if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
			return nil, &SecureBootMaterialError{Step: "writing " + out, Err: err}
		}
	}

	material, err := r.dbSigner(ctx, logger)
	if err != nil {
		return nil, err
	}
	material.CertDir = certDir
	return material, nil
}

// materialResolver resolves one build's references, opening the platform
// clients at most once.
type materialResolver struct {
	build       *ISOBuildConfig
	sb          *installer.SecureBootConfig
	clientsFunc KMSClientsFunc
	clients     *KMSClients
}

// kms returns the operator's platform clients, opening them on first use.
func (r *materialResolver) kms() (*KMSClients, error) {
	if r.clients != nil {
		return r.clients, nil
	}
	if r.clientsFunc == nil {
		return nil, &SecureBootMaterialError{Step: "reaching the KMS", Err: &MessageError{Msg: "the platform config names a kms:// Secure Boot key, and no platform client is configured"}}
	}
	clients, err := r.clientsFunc()
	if err != nil {
		return nil, &SecureBootMaterialError{Step: "connecting to the platform", Err: err}
	}
	r.clients = clients
	return clients, nil
}

// certificate resolves one role's certificate: from the KMS for a kms://
// reference (cert-uri, else the key's id), otherwise from the keys directory
// (the media file a file:// reference names, else <ROLE>.crt).
func (r *materialResolver) certificate(ctx context.Context, role string, ref installer.SecureBootKeyRef) (*x509.Certificate, error) {
	if isKMSRef(ref.CertURI) || (ref.CertURI == "" && isKMSRef(ref.KeyURI)) {
		clients, err := r.kms()
		if err != nil {
			return nil, err
		}
		certRef := secureboot.KMSKeyID(ref.CertURI)
		if certRef == "" {
			certRef = secureboot.KMSKeyID(ref.KeyURI)
		}
		cert, err := secureboot.FetchKMSCertificate(ctx, clients.CA, certRef)
		if err != nil {
			return nil, &SecureBootMaterialError{Step: role + " certificate", Err: err}
		}
		return cert, nil
	}
	name := role + ".crt"
	if file, ok := secureBootMediaFileName(ref.CertURI); ok {
		name = file
	}
	cert, err := authenticode.LoadCertificate(filepath.Join(r.build.KeysDir, name))
	if err != nil {
		return nil, &SecureBootMaterialError{Step: role + " certificate", Err: err}
	}
	return cert, nil
}

// dbSigner builds the DB signer, with its key and certificate: the KMS-held key for a kms:// key-uri, the
// keys directory's pair (the media files a file:// reference names, else
// DB.key / DB.crt) otherwise.
func (r *materialResolver) dbSigner(ctx context.Context, logger *logging.Logger) (*SecureBootMaterial, error) {
	var (
		signer crypto.Signer
		cert   *x509.Certificate
		err    error
	)
	if isKMSRef(r.sb.DB.KeyURI) {
		clients, kmsErr := r.kms()
		if kmsErr != nil {
			return nil, kmsErr
		}
		signer, cert, err = secureboot.NewKMSSigner(ctx, clients.KMS, clients.CA, r.sb.DB.KeyURI, r.sb.DB.CertURI)
	} else {
		keyName, certName := "DB.key", "DB.crt"
		if file, ok := secureBootMediaFileName(r.sb.DB.KeyURI); ok {
			keyName = file
		}
		if file, ok := secureBootMediaFileName(r.sb.DB.CertURI); ok {
			certName = file
		}
		signer, cert, err = authenticode.LoadSigningPair(filepath.Join(r.build.KeysDir, keyName), filepath.Join(r.build.KeysDir, certName))
	}
	if err != nil {
		return nil, &SecureBootMaterialError{Step: "DB signer", Err: err}
	}
	db, err := authenticode.NewCryptoSigner(ctx, signer, cert, logger)
	if err != nil {
		return nil, &SecureBootMaterialError{Step: "DB signer", Err: err}
	}
	return &SecureBootMaterial{DB: db, DBKey: signer, DBCert: cert}, nil
}

// platformSecureBoot decodes the platform config's secure-boot section into the
// platform's one SecureBootConfig definition. A build with no platform config,
// or a config with no section, has no references: every role then comes from
// the keys directory.
func platformSecureBoot(configPath string) (*installer.SecureBootConfig, error) {
	if configPath == "" {
		return &installer.SecureBootConfig{}, nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, &SecureBootMaterialError{Step: "reading " + configPath, Err: err}
	}
	var wrapper struct {
		SecureBoot *installer.SecureBootConfig `yaml:"secure-boot"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, &SecureBootMaterialError{Step: "parsing " + configPath, Err: err}
	}
	if wrapper.SecureBoot == nil {
		return &installer.SecureBootConfig{}, nil
	}
	return wrapper.SecureBoot, nil
}

// isKMSRef reports whether ref is a kms:// reference (case-insensitive).
func isKMSRef(ref string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ref)), "kms://")
}

// SecureBootMaterialError is a build's Secure Boot certificates or DB signer
// that could not be resolved.
type SecureBootMaterialError struct {
	Step string
	Err  error
}

func (e *SecureBootMaterialError) Error() string {
	return "iso: secure boot material: " + e.Step + ": " + e.Err.Error()
}

func (e *SecureBootMaterialError) Unwrap() error { return e.Err }

// InstallMedia is a staged install-media tree and the Secure Boot material it
// was staged with.
type InstallMedia struct {
	// WorkDir is the build's work directory; Dir the staged tree in it.
	WorkDir string
	Dir     string
	// SecureBoot is the build's resolved certificates and DB signer; nil
	// when Secure Boot is off.
	SecureBoot *SecureBootMaterial
	// customizer staged the tree, with the media's configuration.
	customizer *Customizer
}

// InstallerInitramfs rewrites a netboot release's initramfs at path as this
// media's installer initramfs (Customizer.InstallerInitramfs): booted over
// the network with the media as its payload, it runs this media's autoinstall.
func (m *InstallMedia) InstallerInitramfs(ctx context.Context, path string) error {
	return m.customizer.InstallerInitramfs(ctx, path)
}

// StageInstallMedia stages the installer's media tree — the platform binaries,
// the baked platform config with the given installer overrides, the pre-fetched
// packages, the dracut module and the Secure Boot material — into dirName under
// the build's work directory. It is the part every install medium shares: the
// ISO, the factory image, and each netboot media set. The build's architecture
// must already be set.
func StageInstallMedia(ctx context.Context, build *ISOBuildConfig, dirName string, overrides InstallerOverrides, clients KMSClientsFunc, logger *logging.Logger) (*InstallMedia, error) {
	if err := build.Validate(); err != nil {
		return nil, &StageMediaError{Step: "validating the build configuration", Err: err}
	}
	if err := build.ResolveBinaries(); err != nil {
		return nil, &StageMediaError{Step: "resolving the target binaries", Err: err}
	}
	workDir, err := build.ResolveWorkDir()
	if err != nil {
		return nil, &StageMediaError{Step: "resolving the work directory", Err: err}
	}
	decision, err := EnsureSecureBootKeys(ctx, logger, build)
	if err != nil {
		return nil, &StageMediaError{Step: "Secure Boot keys", Err: err}
	}
	logger.Info("[MEDIA] Secure Boot keys", "decision", string(decision), "dir", build.KeysDir)
	material, err := ResolveSecureBootMaterial(ctx, build, clients, logger)
	if err != nil {
		return nil, &StageMediaError{Step: "Secure Boot material", Err: err}
	}

	mediaDir := filepath.Join(workDir, dirName)
	platformCfg := NewPlatformISOConfig(build, workDir)
	platformCfg.Directories.ISO = mediaDir
	platformCfg.Installer = overrides
	platformCfg.Installer.PlatformAPKDir = build.PlatformAPKDir
	if err := platformCfg.Validate(); err != nil {
		return nil, &StageMediaError{Step: "validating the media configuration", Err: err}
	}
	customizer := NewCustomizer(platformCfg, logger)
	if err := customizer.StageMedia(ctx); err != nil {
		return nil, &StageMediaError{Step: "staging the install media", Err: err}
	}
	return &InstallMedia{WorkDir: workDir, Dir: mediaDir, SecureBoot: material, customizer: customizer}, nil
}

// StageMediaError is a step of staging install media that failed.
type StageMediaError struct {
	Step string
	Err  error
}

func (e *StageMediaError) Error() string { return "iso: " + e.Step + ": " + e.Err.Error() }
func (e *StageMediaError) Unwrap() error { return e.Err }
