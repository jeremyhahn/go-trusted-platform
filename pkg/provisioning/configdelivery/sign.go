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

package configdelivery

import (
	"context"
	"errors"
	"log/slog"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// DBKeySigner performs control-plane Secure Boot DB signing on behalf of a
// bare-metal node booting in resign-mode "remote": the DB private key stays in
// the CP-KMS and only the digest crosses the process boundary. The production
// implementation lives daemon-side over the go-quicbaas SDK; tests inject a
// fake. A nil DBKeySigner makes SignDigest return ErrSignerUnavailable.
type DBKeySigner interface {
	// SignDigest signs the pre-computed digest with the DB key identified by
	// keyURI (a kms:// reference). The private key never leaves the KMS.
	SignDigest(ctx context.Context, keyURI string, digest []byte) ([]byte, error)
	// Certificate returns the PEM-encoded DB certificate identified by certRef
	// (the certificate common name) so the node can embed it in the UKI
	// Authenticode signature and enroll it into the firmware signature database.
	Certificate(ctx context.Context, certRef string) ([]byte, error)
}

// SignDigest authenticates a remote resign request and signs the supplied UKI
// (or kernel-module) digest with the control-plane Secure Boot DB key, returning
// the detached signature and the DB certificate. The DB private key never leaves
// the control plane.
//
// Authentication is identical to ResolveConfig — the node has no IDevID yet at
// install time, so it presents EAB credentials, a single-use nonce, and (when
// the matched profile is EK-bound) its TPM Endorsement Key certificate. EAB and
// EK verification are enforced BEFORE the digest is ever signed.
func (s *Service) SignDigest(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// Fail fast when no DB signer is wired: the control plane cannot honor
	// remote signing at all, which is a configuration/availability condition
	// distinct from any per-request rejection.
	if s.dbKeySigner == nil {
		return nil, ErrSignerUnavailable{}
	}

	if err := validateIdentityFields(req.EKSerial, req.MACAddress, req.EABKeyID, req.EABHMAC, req.Nonce); err != nil {
		return nil, err
	}
	if len(req.Digest) == 0 {
		return nil, ErrInvalidRequest{Reason: "digest is required"}
	}

	// Same pre-enrollment authentication as ResolveConfig: single-use nonce
	// followed by External Account Binding validation.
	cred, err := s.verifyNonceAndEAB(ctx, req.Nonce, req.EABKeyID, req.EABHMAC)
	if err != nil {
		return nil, err
	}

	if s.profileService == nil {
		return nil, ErrMissingProfileService{}
	}

	profile, err := s.profileService.FindConfigForDevice(ctx, req.EKSerial, req.MACAddress)
	if err != nil {
		var noMatch device.ErrNoMatchingConfig
		if errors.As(err, &noMatch) {
			return nil, ErrRemoteSignNotConfigured{Reason: "no device profile matched the request identity"}
		}
		return nil, err
	}

	if err := verifyEABBinding(cred, profile); err != nil {
		s.logger.Warn("configdelivery: sign eab credential bound to another profile",
			slog.Uint64("profile_id", profile.ID),
			slog.String("ek_serial", req.EKSerial),
			slog.String("mac_address", req.MACAddress))
		return nil, err
	}

	// Cryptographically bind the signing request to the device's hardware EK,
	// exactly as ResolveConfig binds delivered config. A missing or mismatched
	// EK certificate rejects the request before any signing occurs.
	if err := s.verifyEKBinding(profile, req.EKCert); err != nil {
		s.logger.Warn("configdelivery: sign ek binding verification failed",
			slog.Uint64("profile_id", profile.ID),
			slog.String("ek_serial", req.EKSerial),
			slog.String("mac_address", req.MACAddress),
			slog.String("error", err.Error()))
		return nil, err
	}

	keyURI, certCN, err := remoteDBKeyRefs(profile, req.KeyRef)
	if err != nil {
		s.logger.Warn("configdelivery: remote signing not configured",
			slog.Uint64("profile_id", profile.ID),
			slog.String("error", err.Error()))
		return nil, err
	}

	signature, err := s.dbKeySigner.SignDigest(ctx, keyURI, req.Digest)
	if err != nil {
		return nil, ErrSignFailed{Cause: err}
	}

	certPEM, err := s.dbKeySigner.Certificate(ctx, certCN)
	if err != nil {
		return nil, ErrCertUnavailable{Cause: err}
	}

	s.logger.Info("configdelivery: remote uki digest signed",
		slog.Uint64("profile_id", profile.ID),
		slog.String("ek_serial", req.EKSerial),
		slog.String("mac_address", req.MACAddress),
		slog.String("key_uri", keyURI))

	return &SignResponse{Signature: signature, CertPEM: certPEM}, nil
}

// validateIdentityFields verifies the shared pre-enrollment request fields used
// by both ConfigRequest and SignRequest: EAB credentials, a nonce, and at least
// one device identifier. It is the field-presence half of the authentication
// reused by validateRequest and SignDigest.
func validateIdentityFields(ekSerial, mac, eabKeyID, eabHMAC, nonce string) error {
	if eabKeyID == "" {
		return ErrInvalidRequest{Reason: "eab_key_id is required"}
	}
	if eabHMAC == "" {
		return ErrInvalidRequest{Reason: "eab_hmac is required"}
	}
	if nonce == "" {
		return ErrNonceRequired{}
	}
	if ekSerial == "" && mac == "" {
		return ErrInvalidRequest{Reason: "at least one of ek_serial or mac_address is required"}
	}
	return nil
}

// remoteDBKeyRefs extracts, from a resolved profile, the CP-KMS DB signing key
// URI and the DB certificate common name for the requested key selector. It
// enforces the remote-signing preconditions: secure boot enabled, resign-mode
// "remote" (an empty mode defaults to remote, matching installer.SecureBootConfig),
// a non-empty DB key URI, and a supported selector — only "db" is remotely
// signed; PK/KEK are TPM-resident. Any unmet precondition is reported as
// ErrRemoteSignNotConfigured so the node learns this device is not provisioned
// for remote signing rather than receiving an opaque failure.
func remoteDBKeyRefs(profile *entities.DeviceProfile, keyRef string) (keyURI, certCN string, err error) {
	if keyRef == "" {
		keyRef = "db"
	}
	if keyRef != "db" {
		return "", "", ErrRemoteSignNotConfigured{Reason: "only the db key supports remote signing"}
	}

	sb, err := secureBootFromProfile(profile)
	if err != nil {
		return "", "", err
	}
	if !sb.Enabled {
		return "", "", ErrRemoteSignNotConfigured{Reason: "secure boot is not enabled for this device"}
	}
	mode := sb.ResignMode
	if mode == "" {
		mode = installer.SecureBootResignModeRemote
	}
	if mode != installer.SecureBootResignModeRemote {
		return "", "", ErrRemoteSignNotConfigured{Reason: "resign-mode is not remote"}
	}
	if sb.DB.KeyURI == "" {
		return "", "", ErrRemoteSignNotConfigured{Reason: "no secure-boot db key-uri configured"}
	}
	return sb.DB.KeyURI, sb.DB.CN, nil
}

// secureBootFromProfile decodes the secure-boot section of a resolved device
// profile's platform config into the canonical installer.SecureBootConfig. The
// profile config is stored type-erased (map[string]interface{} from the device
// template, or *app.App), so the section is recovered by re-serializing the
// config and decoding the "secure-boot" key into the typed struct. This keeps
// the platform's single SecureBootConfig definition authoritative rather than
// re-deriving the field layout here. A config read from the profile store
// holds json.Number values, which entities.MarshalConfigYAML emits as plain
// YAML numbers so they decode into the struct's integer fields.
func secureBootFromProfile(profile *entities.DeviceProfile) (*installer.SecureBootConfig, error) {
	if profile == nil || profile.Config == nil {
		return nil, ErrRemoteSignNotConfigured{Reason: "device profile has no platform config"}
	}
	raw, err := entities.MarshalConfigYAML(profile.Config)
	if err != nil {
		return nil, ErrRemoteSignNotConfigured{Reason: "platform config is not serializable"}
	}
	var wrapper struct {
		SecureBoot *installer.SecureBootConfig `yaml:"secure-boot"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err != nil {
		return nil, ErrRemoteSignNotConfigured{Reason: "secure-boot config did not decode"}
	}
	if wrapper.SecureBoot == nil {
		return nil, ErrRemoteSignNotConfigured{Reason: "no secure-boot section in profile config"}
	}
	return wrapper.SecureBoot, nil
}
