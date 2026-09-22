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

package daemon

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultLDevIDHandle is the persistent TPM handle for the LDevID signing key.
// It is deliberately distinct from the IDevID (0x81010100) and IAK (0x81010101)
// birth-key handles so an LDevID never collides with the permanent identity keys.
const defaultLDevIDHandle = uint32(0x81010102)

// ErrIDevIDNotEnrolled is returned when LDevID issuance is requested for a
// device that has no proven IDevID. LDevID is a locally significant, CA-issued
// operational identity that layers on top of the permanent IDevID birth
// identity, so the platform refuses to issue one until the device has a valid,
// currently-time-valid IDevID certificate installed — the on-device
// materialization of a successful enroll-01 / endorse-01 attestation.
type ErrIDevIDNotEnrolled struct {
	Reason string
}

// Error implements the error interface.
func (e ErrIDevIDNotEnrolled) Error() string {
	return "idevid: LDevID refused, device has no proven IDevID: " + e.Reason
}

// ErrLDevIDCANotConfigured is returned when CreateLDevID is invoked but no
// certificate authority is wired into the service to issue the LDevID.
type ErrLDevIDCANotConfigured struct{}

// Error implements the error interface.
func (ErrLDevIDCANotConfigured) Error() string {
	return "idevid: certificate authority not configured for LDevID issuance"
}

// SetCAService wires the platform certificate authority used to issue LDevID
// certificates. It is the same CA seam used elsewhere in the daemon
// (config.CAService) and is reached exclusively through the quicbaas SDK.
func (s *IDevIDGRPCService) SetCAService(ca quicbaasca.CACertificateAuthority) {
	s.ca = ca
}

// ldevidSigner adapts a TPM-resident LDevID key to the crypto.Signer interface
// so the standard library can build a PKCS#10 CSR from it. It mirrors the
// platform.TPMSigner reuse pattern but carries the public key returned by the
// key-creation call, guaranteeing Public() is populated for
// x509.CreateCertificateRequest. Signing is delegated to the TPM, which works
// identically on a hardware TPM and swtpm via the TrustedPlatformModule seam.
type ldevidSigner struct {
	tpm     xkmssdk.TrustedPlatformModule
	attrs   *xkmssdk.KeyAttributes
	backend xkmssdk.TPMKeyBackend
	pub     crypto.PublicKey
}

// Public returns the LDevID public key.
func (s *ldevidSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest with the TPM-resident LDevID key. The TPM derives the
// hash from the key attributes, so the crypto.SignerOpts hash is advisory only,
// consistent with the platform's other TPM signer wrappers.
func (s *ldevidSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.tpm.Sign(rand.Reader, digest, &xkmssdk.TPMSignerOpts{
		KeyAttributes: s.attrs,
		Backend:       s.backend,
	})
}

// CreateLDevID provisions a Local Device Identifier (IEEE 802.1AR). It creates
// a TPM-resident LDevID signing key distinct from the IDevID/IAK birth keys,
// builds a PKCS#10 CSR signed by that key, and has the platform CA issue the
// certificate. Issuance is gated on a proven IDevID: a device with no valid
// installed IDevID certificate is refused with FailedPrecondition.
func (s *IDevIDGRPCService) CreateLDevID(ctx context.Context, req *platformv1.CreateLDevIDRequest) (*platformv1.CreateLDevIDResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrLDevIDCANotConfigured{}.Error())
	}

	// ---- Gate: refuse LDevID without a proven, currently-valid IDevID. ----
	idevidCert, err := s.tpm2Service.IDevIDCertificate()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition,
			ErrIDevIDNotEnrolled{Reason: "no IDevID certificate installed: " + err.Error()}.Error())
	}
	if idevidCert == nil {
		return nil, status.Error(codes.FailedPrecondition,
			ErrIDevIDNotEnrolled{Reason: "no IDevID certificate installed"}.Error())
	}
	now := time.Now()
	if now.Before(idevidCert.NotBefore) || now.After(idevidCert.NotAfter) {
		return nil, status.Error(codes.FailedPrecondition,
			ErrIDevIDNotEnrolled{Reason: "IDevID certificate is not within its validity window"}.Error())
	}

	// ---- Resolve the LDevID key parameters. ----
	handle := req.GetHandle()
	if handle == 0 {
		handle = defaultLDevIDHandle
	}

	keyAlgo, keyAlgoStr, hashStr, sigAlgoStr, eccCfg, rsaCfg := ldevidAlgorithmParams(req.GetAlgorithm())

	cn := ""
	if tmpl := req.GetTemplate(); tmpl != nil {
		cn = tmpl.GetCommonName()
	}
	if cn == "" {
		cn = idevidCert.Subject.CommonName
	}
	if cn == "" {
		cn = "ldevid"
	}

	ldevidCfg := xkmssdk.LDevIDConfig{
		Handle:             handle,
		CN:                 cn,
		KeyAlgorithm:       keyAlgoStr,
		Hash:               hashStr,
		SignatureAlgorithm: sigAlgoStr,
		ECCConfig:          eccCfg,
		RSAConfig:          rsaCfg,
	}

	attrs, err := xkmssdk.LDevIDAttributesFromConfig(ldevidCfg)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "build LDevID attributes: "+err.Error())
	}

	// The LDevID key is created as a child of the platform key store SRK,
	// reusing the same backend the platform uses for all TPM-resident keys.
	pks := s.tpm2Service.PlatformKeyStore()
	if pks == nil {
		return nil, status.Error(codes.Unavailable, "platform key store not available for LDevID key creation")
	}
	attrs.Parent = pks.SRKAttributes()
	backend := pks.Backend()

	// ---- Create the TPM-resident LDevID signing key. ----
	var pub crypto.PublicKey
	switch keyAlgo {
	case x509.ECDSA:
		ecPub, ecErr := s.tpm2Service.CreateECDSA(attrs, backend, req.GetOverwrite())
		if ecErr != nil {
			s.logger.Error(ecErr, "Failed to create LDevID ECDSA key")
			return nil, s.mapTPM2Error(ecErr, "create LDevID key")
		}
		pub = ecPub
	case x509.RSA:
		rsaPub, rsaErr := s.tpm2Service.CreateRSA(attrs, backend, req.GetOverwrite())
		if rsaErr != nil {
			s.logger.Error(rsaErr, "Failed to create LDevID RSA key")
			return nil, s.mapTPM2Error(rsaErr, "create LDevID key")
		}
		pub = rsaPub
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported LDevID key algorithm")
	}

	// ---- Build a PKCS#10 CSR signed by the LDevID key. ----
	signer := &ldevidSigner{tpm: s.tpm2Service, attrs: attrs, backend: backend, pub: pub}
	csrTemplate := ldevidCSRTemplate(cn, req.GetTemplate())

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		s.logger.Error(err, "Failed to build LDevID CSR")
		return nil, status.Error(codes.Internal, "build LDevID CSR: "+err.Error())
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// ---- Issue the LDevID certificate from the platform CA. ----
	cert, err := s.ca.SignCSR(ctx, csrPEM, &quicbaasca.SignOptions{
		Profile:      req.GetProfile(),
		ValidityDays: int(req.GetValidityDays()),
	})
	if err != nil {
		s.logger.Error(err, "Failed to issue LDevID certificate")
		return nil, status.Error(codes.Internal, "issue LDevID certificate: "+err.Error())
	}

	protoCert := s.certToProto(cert)
	if protoCert != nil {
		protoCert.KeyType = "LDevID"
		protoCert.TpmHandle = handle
	}

	s.logger.Info("LDevID certificate issued", "cn", cn, "handle", handle)

	var certPEM []byte
	if protoCert != nil {
		certPEM = protoCert.Pem
	}

	return &platformv1.CreateLDevIDResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "LDevID certificate issued successfully",
		},
		CsrPem:         csrPEM,
		CertificatePem: certPEM,
		Certificate:    protoCert,
	}, nil
}

// ldevidAlgorithmParams maps the proto DeviceKeyAlgorithm to the concrete key
// generation parameters. Unspecified defaults to ECDSA P-256, the TCG-preferred
// device identity algorithm.
func ldevidAlgorithmParams(algo platformv1.DeviceKeyAlgorithm) (
	keyAlgo x509.PublicKeyAlgorithm,
	keyAlgoStr, hashStr, sigAlgoStr string,
	eccCfg *xkmssdk.ECCConfig,
	rsaCfg *xkmssdk.RSAConfig,
) {
	switch algo {
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384:
		return x509.ECDSA, "ECDSA", "SHA-384", "ECDSA-SHA384", &xkmssdk.ECCConfig{Curve: "P-384"}, nil
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048:
		return x509.RSA, "RSA", "SHA-256", "SHA256-RSA", nil, &xkmssdk.RSAConfig{KeySize: 2048}
	case platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072:
		return x509.RSA, "RSA", "SHA-256", "SHA256-RSA", nil, &xkmssdk.RSAConfig{KeySize: 3072}
	default:
		// DEVICE_KEY_ALGORITHM_UNSPECIFIED and DEVICE_KEY_ALGORITHM_ECDSA_P256.
		return x509.ECDSA, "ECDSA", "SHA-256", "ECDSA-SHA256", &xkmssdk.ECCConfig{Curve: "P-256"}, nil
	}
}

// ldevidCSRTemplate builds the x509 CSR template from the request template,
// defaulting the subject common name to the resolved cn.
func ldevidCSRTemplate(cn string, tmpl *platformv1.CSRTemplate) *x509.CertificateRequest {
	subject := pkix.Name{CommonName: cn}
	csr := &x509.CertificateRequest{}
	if tmpl != nil {
		if v := tmpl.GetOrganization(); v != "" {
			subject.Organization = []string{v}
		}
		if v := tmpl.GetOrganizationalUnit(); v != "" {
			subject.OrganizationalUnit = []string{v}
		}
		if v := tmpl.GetCountry(); v != "" {
			subject.Country = []string{v}
		}
		if v := tmpl.GetProvince(); v != "" {
			subject.Province = []string{v}
		}
		if v := tmpl.GetLocality(); v != "" {
			subject.Locality = []string{v}
		}
		csr.DNSNames = tmpl.GetDnsNames()
		csr.EmailAddresses = tmpl.GetEmailAddresses()
	}
	csr.Subject = subject
	return csr
}
