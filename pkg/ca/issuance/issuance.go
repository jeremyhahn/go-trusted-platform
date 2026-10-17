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

// Package issuance holds the rules every CA transport (gRPC, Unix, embedded,
// REST, QUIC, MCP) applies to "ca issue" and "ca sign-csr" requests, so they
// cannot disagree: which key store a store name selects, and which CSRs the
// CA certifies, for what.
package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"strings"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// csrPEMType is the PEM block type of a PKCS#10 request.
const csrPEMType = "CERTIFICATE REQUEST"

// CA is the slice of the platform CA that issuance needs.
type CA interface {
	SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error)
}

// storeAliases are the store names the CLI has always documented that the
// upstream parser does not know: no name means the software store, PKCS#8
// is the software store's key format, and "tpm" is TPM 2.0.
var storeAliases = map[string]xkmssdk.StoreType{
	"":      xkmssdk.StoreSoftware,
	"pkcs8": xkmssdk.StoreSoftware,
	"tpm":   xkmssdk.StoreTPM2,
}

// StoreType returns the key store a request names. A name no store answers
// to is an error: it never falls back to a new software key, which would
// certify a key the caller did not ask for.
func StoreType(name string) (xkmssdk.StoreType, error) {
	if store, ok := storeAliases[strings.ToLower(name)]; ok {
		return store, nil
	}
	store := xkmssdk.ParseStoreType(name)
	if store == xkmssdk.StoreUnknown {
		return store, &UnknownStoreTypeError{Name: name}
	}
	return store, nil
}

// KMS is the slice of the platform KMS that SignCSR needs: the public key
// of the key a CSR names.
type KMS interface {
	GetPublicKey(ctx context.Context, req *baasservice.GetPublicKeyRequest) (*baasservice.GetPublicKeyResponse, error)
}

// clientKMS is the KMS of an SDK KMS client, which the webservice holds
// rather than the KMS service the daemon transports hold.
type clientKMS struct {
	client kmsclient.Client
}

// ClientKMS returns the KMS behind an SDK KMS client, or nil when there is
// no client, so SignCSR fails closed.
func ClientKMS(client kmsclient.Client) KMS {
	if client == nil {
		return nil
	}
	return clientKMS{client: client}
}

func (k clientKMS) GetPublicKey(ctx context.Context, req *baasservice.GetPublicKeyRequest) (*baasservice.GetPublicKeyResponse, error) {
	resp, err := k.client.GetPublicKey(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}
	return &baasservice.GetPublicKeyResponse{KeyID: resp.KeyID, PublicKey: resp.PublicKey}, nil
}

// CSR is a request to certify a KMS key from a PKCS#10 CSR the KMS signed.
type CSR struct {
	// PEM is the CSR. Its common name is the KMS key's ID.
	PEM       []byte
	ValidDays int
}

// SignCSRScope is the platform-token scope that certifies a KMS key from a
// CSR. It is an admin scope of its own: certs:generate, which issues
// ordinary certificates, does not grant it.
const SignCSRScope = "ca:sign-csr"

// AuthorizeSignCSR requires that authCtx, the caller's validated platform
// token, grants SignCSRScope. A caller authenticated without a platform
// token (mTLS, a legacy token validator) has no scopes, so it passes nil
// and is refused: no transport certifies a code-signing key on
// authentication alone.
//
// A tokenless mTLS peer on MCP or QUIC does carry an AuthorizedContext, the
// operator's, with scopes a token would grant. Its transport marks ctx with
// peercred.ContextWithCertificatePrincipal, and that principal is refused
// here whatever its scopes, so the rule holds wherever the context came from
// (docs/ca/api.md, "Sign CSR needs ca:sign-csr").
func AuthorizeSignCSR(ctx context.Context, authCtx *platformtoken.AuthorizedContext) error {
	if peercred.IsCertificatePrincipal(ctx) {
		return &SignCSRScopeError{Reason: "the caller presented a client certificate alone"}
	}
	if authCtx == nil {
		return &SignCSRScopeError{Reason: "the caller presented no platform token"}
	}
	if err := authCtx.RequireScope(SignCSRScope); err != nil {
		return &SignCSRScopeError{Reason: err.Error()}
	}
	return nil
}

// codeSigningUsage is the only use a certified KMS key is put to: signing
// boot artifacts. It is fixed rather than requested, so this path can never
// mint a TLS server or client identity.
var codeSigningUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

// SignCSR certifies a KMS key for code signing with the platform CA.
//
// It refuses, before the CA is reached, any CSR that could name anything
// but the key: a subject attribute other than the common name, or a subject
// alternative name. The common name must name a key kms holds, and the
// CSR's key must be that key, so the certificate binds only a name to the
// key the KMS already knows by it. A refused CSR is the caller's error
// (IsInvalidRequest).
func SignCSR(ctx context.Context, ca CA, kms KMS, req *CSR) (*x509.Certificate, error) {
	csr, err := parseCSR(req.PEM)
	if err != nil {
		return nil, err
	}
	if err := checkNamesOnlyTheKey(csr); err != nil {
		return nil, err
	}
	cn := csr.Subject.CommonName
	if err := checkKMSKey(ctx, kms, cn, csr.PublicKey); err != nil {
		return nil, err
	}
	cert, err := ca.SignCSR(ctx, req.PEM, &quicbaasca.SignOptions{
		ValidityDays: req.ValidDays,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  codeSigningUsage,
	})
	if err != nil {
		return nil, &SignCSRError{CommonName: cn, Err: err}
	}
	return cert, nil
}

// parseCSR decodes a PEM CSR and checks its self-signature, which proves the
// requester holds the key, and that it names a subject the CA can store the
// certificate under.
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != csrPEMType {
		return nil, &CSRError{Reason: "it is not a PEM " + csrPEMType}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, &CSRError{Reason: "it does not parse", Err: err}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &CSRError{Reason: "its signature does not verify under its own key", Err: err}
	}
	if csr.Subject.CommonName == "" {
		return nil, &CSRError{Reason: "it has no common name"}
	}
	return csr, nil
}

// oidCommonName is the X.520 commonName attribute.
const oidCommonName = "2.5.4.3"

// subjectAttributeNames are the short names of the subject attributes Go
// knows, for error messages; any other attribute is named by its OID.
var subjectAttributeNames = map[string]string{
	oidCommonName: "CN",
	"2.5.4.5":     "serialNumber",
	"2.5.4.6":     "C",
	"2.5.4.7":     "L",
	"2.5.4.8":     "ST",
	"2.5.4.9":     "street",
	"2.5.4.10":    "O",
	"2.5.4.11":    "OU",
	"2.5.4.17":    "postalCode",
}

// checkNamesOnlyTheKey refuses a CSR whose subject is anything but one
// common name, or which carries subject alternative names. The CA copies
// both into the certificate, and the platform's mTLS reads an identity from
// CN and a tenant from O.
func checkNamesOnlyTheKey(csr *x509.CertificateRequest) error {
	var extra []string
	seenCN := false
	for _, attr := range csr.Subject.Names {
		oid := attr.Type.String()
		if oid == oidCommonName && !seenCN {
			seenCN = true
			continue
		}
		name, ok := subjectAttributeNames[oid]
		if !ok {
			name = oid
		}
		extra = append(extra, name)
	}
	if len(extra) > 0 {
		return &CSRSubjectError{Attributes: extra}
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return &CSRSANError{}
	}
	return nil
}

// checkKMSKey requires that kms holds a key named keyID whose public key is
// public.
func checkKMSKey(ctx context.Context, kms KMS, keyID string, public crypto.PublicKey) error {
	if kms == nil {
		return &KMSUnavailableError{}
	}
	resp, err := kms.GetPublicKey(ctx, &baasservice.GetPublicKeyRequest{KeyID: keyID})
	if err != nil {
		return &CSRKeyError{KeyID: keyID, Err: err}
	}
	kmsPublic, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return &KMSPublicKeyError{KeyID: keyID, Err: err}
	}
	key, ok := kmsPublic.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !key.Equal(public) {
		return &CSRKeyMismatchError{KeyID: keyID}
	}
	return nil
}
