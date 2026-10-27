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

package v1

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/adminclaim"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/system"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	sdktransport "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"

	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// AttestationImporter defines the minimal interface required for importing
// attestation data from TCG enrollments. This interface is satisfied by
// ca.CertificateAuthority and allows for easier testing with mocks.
type AttestationImporter interface {
	ImportAttestationEventLog(ctx context.Context, akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error
	ImportAttestationQuote(ctx context.Context, akAttrs *xkmssdk.KeyAttributes, quote []byte) error
	ImportAttestationPCRs(ctx context.Context, akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error
}

// NewAttestationImportHook creates an order finalization hook that imports
// client attestation data after successful device enrollment. This captures
// the event log, TPM quote, and PCR values from TCG enrollments and stores
// them in the CA's attestation store.
//
// The attestation data is transmitted from the client via:
//   - EventLog: TCG-CSR-IDEVID BootEvntLog field
//   - Quote + PCRs: TCG-CSR-IDEVID ProdCaData field (packed as ProdCaData structure)
//
// This hook is defined within go-trusted-platform and registered with the CA's
// generic hook registry.
func NewAttestationImportHook(caInstance AttestationImporter, logger *slog.Logger) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		logger.Info("Attestation import hook called",
			slog.Bool("is_tcg_csr", ctx.IsTCGCSR),
			slog.Bool("tcg_data_nil", ctx.TCGData == nil),
			slog.String("client_ip", ctx.ClientIP))

		// Only import attestation for TCG enrollments (device enrollment via enroll-01)
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			logger.Info("Skipping attestation import - not a TCG CSR enrollment")
			return nil
		}

		// Create key attributes for the enrolled device using certificate CN
		akAttrs := &xkmssdk.KeyAttributes{
			CN: ctx.Certificate.Subject.CommonName,
		}

		// Import the event log if available (from BootEvntLog field)
		if len(ctx.TCGData.EventLog) > 0 {
			logger.Info("Importing attestation event log",
				slog.String("cn", akAttrs.CN),
				slog.Int("event_log_size", len(ctx.TCGData.EventLog)))

			if err := caInstance.ImportAttestationEventLog(ctx.Context, akAttrs, ctx.TCGData.EventLog); err != nil {
				logger.Error("Failed to import attestation event log",
					slog.String("cn", akAttrs.CN),
					slog.String("error", err.Error()))
				return &WrappedError{Msg: fmt.Sprintf("failed to import attestation event log for %s", akAttrs.CN), Err: err}
			}

			logger.Info("Successfully imported attestation event log",
				slog.String("cn", akAttrs.CN),
				slog.String("model", ctx.TCGData.ProductModel),
				slog.String("serial", ctx.TCGData.ProductSerial))
		} else {
			logger.Info("No event log data available in TCG enrollment",
				slog.String("cn", akAttrs.CN))
		}

		// Import Quote and PCRs from ProdCaData if available
		if len(ctx.TCGData.ProdCaData) > 0 {
			logger.Info("Importing attestation data from ProdCaData",
				slog.String("cn", akAttrs.CN),
				slog.Int("prodcadata_size", len(ctx.TCGData.ProdCaData)))

			// Unpack the ProdCaData structure
			prodCaData, err := xkmssdk.UnpackProdCaData(ctx.TCGData.ProdCaData)
			if err != nil {
				logger.Error("Failed to unpack ProdCaData",
					slog.String("cn", akAttrs.CN),
					slog.String("error", err.Error()))
				return &WrappedError{Msg: fmt.Sprintf("failed to unpack ProdCaData for %s", akAttrs.CN), Err: err}
			}

			if prodCaData != nil {
				// Convert ProdCaData to Quote structure
				quote := prodCaData.ToQuote()

				// Import Quote (store the Quoted data - matches local attestation behavior)
				if len(quote.Quoted) > 0 {
					if err := caInstance.ImportAttestationQuote(ctx.Context, akAttrs, quote.Quoted); err != nil {
						logger.Error("Failed to import attestation quote",
							slog.String("cn", akAttrs.CN),
							slog.String("error", err.Error()))
						return &WrappedError{Msg: fmt.Sprintf("failed to import attestation quote for %s", akAttrs.CN), Err: err}
					}

					logger.Info("Successfully imported attestation quote",
						slog.String("cn", akAttrs.CN),
						slog.Int("quoted_size", len(quote.Quoted)),
						slog.Int("signature_size", len(quote.Signature)),
						slog.Int("nonce_size", len(quote.Nonce)))
				}

				// Import PCRs
				if len(quote.PCRs) > 0 {
					if err := caInstance.ImportAttestationPCRs(ctx.Context, akAttrs, quote.PCRs); err != nil {
						logger.Error("Failed to import attestation PCRs",
							slog.String("cn", akAttrs.CN),
							slog.String("error", err.Error()))
						return &WrappedError{Msg: fmt.Sprintf("failed to import attestation PCRs for %s", akAttrs.CN), Err: err}
					}

					logger.Info("Successfully imported attestation PCRs",
						slog.String("cn", akAttrs.CN),
						slog.Int("pcrs_size", len(quote.PCRs)))
				}
			}
		} else {
			logger.Info("No ProdCaData available in TCG enrollment (quote and PCRs not submitted)",
				slog.String("cn", akAttrs.CN))
		}

		return nil
	}
}

// DeviceRegistrar is the minimal slice of devicepkg.DeviceService the
// device-registration finalize hook needs. It is devicepkg.Registrar, the
// same surface the control-plane self-registration writes through (#472),
// aliased here so existing callers and tests keep the local name.
type DeviceRegistrar = devicepkg.Registrar

// NewDeviceRegistrationHook creates an order finalization hook that
// materialises an enrolled device in the platform's device service.
// Without this hook the CA mints the IDevID and persists the certificate
// but the platform's device inventory stays empty — the WebUI Devices
// page would never show the device, and downstream consumers
// (attestation gate, SDN policy, dashboard counters) have nothing to
// join against.
//
// The hook is a no-op for non-TCG enrollments — only TCG-CSR-IDEVID
// flows have product model/serial metadata to bind a Device row to.
//
// Idempotency: the hook looks up an existing Device by ProductSerial
// before allocating a new one. Re-enrollment of the same device updates
// the existing row instead of creating a duplicate.
func NewDeviceRegistrationHook(deviceService DeviceRegistrar, logger *slog.Logger) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		logger.Info("Device registration hook called",
			slog.Bool("is_tcg_csr", ctx.IsTCGCSR),
			slog.Bool("tcg_data_nil", ctx.TCGData == nil),
			slog.String("client_ip", ctx.ClientIP))

		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			logger.Info("Skipping device registration - not a TCG CSR enrollment")
			return nil
		}

		serial := strings.TrimSpace(ctx.TCGData.ProductSerial)
		if serial == "" {
			logger.Warn("Device registration: TCG enrollment has no ProductSerial - skipping",
				slog.String("client_ip", ctx.ClientIP))
			return nil
		}

		// The CA issued the IAK certificate in the same finalize that issued
		// the IDevID (SignTCGCSRIDevID); it arrives here as DER. It is the
		// only trust anchor the quote verifier accepts (#374), so an
		// enrollment that does not record it leaves the device unable to
		// attest (#404).
		//
		// Everything below the field mapping — find-or-create by serial,
		// the index-drift guard, the skip-empty writes — is devicepkg.Register,
		// the one registration implementation. The control plane writes its
		// own record through the same function from its own TPM (#472), so an
		// enrolled node and the control plane are the same kind of record.
		//
		// The issued certificate is the IDevID. Its chain and Common Name are
		// recorded so a diskless node, which keeps neither across a reboot,
		// can fetch the chain back by that name and present it over mTLS
		// with its TPM-resident key (#690).
		idevidChain, err := issuedChainPEM(ctx.CertificatePEM, ctx.Certificate)
		if err != nil {
			return err
		}
		result, err := devicepkg.Register(ctx.Context, deviceService, devicepkg.Registration{
			Model:         ctx.TCGData.ProductModel,
			Serial:        serial,
			Hostname:      issuedCommonName(ctx.Certificate),
			EKCertPEM:     devicepkg.EncodeCertificatePEM(ctx.TCGData.EKCertificate),
			AttestCertPEM: devicepkg.EncodeCertificateDERPEM(ctx.TCGData.IAKCertificateDER),
			IDevIDCertPEM: idevidChain,
			AttestPub:     ctx.TCGData.AttestationPublicKey,
			SigningPub:    ctx.TCGData.SigningPublicKey,
			EventLog:      ctx.TCGData.EventLog,
		}, time.Now().UTC())
		if err != nil {
			return err
		}
		if result.AttestCertWarning != "" {
			// Not recording it is the safe outcome: an attestation
			// certificate the platform cannot verify turns this device's
			// next collection from "no evidence" into a cryptographic
			// failure, which quarantines it.
			logger.Warn("Device registration: attestation certificate not recorded",
				slog.String("serial", serial),
				slog.String("reason", result.AttestCertWarning))
		}
		if result.LookupWarning != "" {
			logger.Warn("Device registration: existing record not reused",
				slog.String("serial", serial),
				slog.String("reason", result.LookupWarning))
		}
		logger.Info("Device registration: device recorded",
			slog.String("serial", serial),
			slog.String("model", result.Device.Model),
			slog.Uint64("device_id", result.Device.ID),
			slog.Bool("created", result.Created))
		return nil
	}
}

// issuedCommonName returns the issued certificate's Common Name, or "" when
// the finalize carried no parsed certificate.
func issuedCommonName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

// issuedChainPEM returns the IDevID chain to record: the issued IDevID leaf
// first, then the CA certificates of the issuing chain.
//
// It does not trust the order of the finalize PEM. enroll-01 delivers two
// end-entity certificates before the chain, the IAK and then the IDevID, so
// the PEM's first certificate is the IAK. A diskless node presents the
// recorded chain as its mTLS identity and proves the key of its first
// certificate (BootService.Certificate), so only the IDevID may lead it.
// Every end-entity certificate in the PEM, the IAK and the IDevID itself
// included, is therefore dropped and the leaf put back in front.
func issuedChainPEM(chainPEM []byte, leaf *x509.Certificate) (string, error) {
	recorded := devicepkg.EncodeCertificatePEM(leaf)
	if recorded == "" || len(chainPEM) == 0 {
		return recorded, nil
	}
	chain, err := provisioning.ParseCertificateChain(chainPEM)
	if err != nil {
		return "", ErrIssuedChainInvalid{Cause: err}
	}
	for _, cert := range chain {
		if cert.IsCA {
			recorded += devicepkg.EncodeCertificatePEM(cert)
		}
	}
	return recorded, nil
}

// ErrIssuedChainInvalid is returned by the device registration hook when the
// certificate chain the CA issued does not parse. Recording it anyway would
// leave a diskless node with an identity it cannot present.
type ErrIssuedChainInvalid struct {
	Cause error
}

func (e ErrIssuedChainInvalid) Error() string {
	return "device registration: issued certificate chain does not parse: " + e.Cause.Error()
}

func (e ErrIssuedChainInvalid) Unwrap() error { return e.Cause }

// NewDNSRegistrationHook creates an order finalization hook that registers
// DNS records for enrolled devices. This hook is called by go-trusted-ca's
// generic hook system after successful order finalization.
//
// The CA has no knowledge of DNS - this hook is entirely defined within
// go-trusted-platform and registered with the CA's generic hook registry.
//
// When profiles is non-nil and zone_subdomains is enabled on the DNS service,
// the hook additionally registers the device hostname under its network zone
// subdomain (<host>.<networkZone>.<domain>) IN ADDITION to the standard
// <host>.<domain> record. BMC names are never zone-qualified. This is a
// reflect-only DNS operation; no SDN policy is affected.
func NewDNSRegistrationHook(
	dnsService DNSRegistrar,
	internalDomain string,
	logger *slog.Logger,
	profiles ZoneProfileResolver,
) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		logger.Info("DNS registration hook called",
			slog.Bool("is_tcg_csr", ctx.IsTCGCSR),
			slog.Bool("tcg_data_nil", ctx.TCGData == nil),
			slog.String("client_ip", ctx.ClientIP))

		// Only register DNS for TCG enrollments (device enrollment via enroll-01)
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			logger.Info("Skipping DNS registration - not a TCG CSR enrollment")
			return nil
		}

		// Build the canonical set of FQDNs to register. Two sources:
		//
		//   1. Hardware identity (model-serial). The TCG CSR's
		//      ProductModel + ProductSerial map deterministically to a
		//      single FQDN under the internal zone — used for
		//      attestation correlation and audit log lookup. Always
		//      created when both fields are present.
		//
		//   2. Operator-friendly hostnames from the issued IDevID
		//      certificate's SAN list. Any DNS SAN that falls inside
		//      the internal-domain zone is registered as an A record
		//      pointing at the client IP. This is what makes
		//      `gw.example.internal` resolvable from the moment the GW
		//      finishes enroll-01 — without it, operators have to
		//      query opaque `Super-Server-node-01-gw-01.example.internal`
		//      records to find each node.
		//
		// Wildcards, cross-zone SANs, and CN duplicates are filtered
		// in collectFQDNsForInternalZone so the final set is exactly
		// the records we expect to publish.
		fqdns := collectFQDNsForInternalZone(ctx, internalDomain)
		if len(fqdns) == 0 {
			logger.Warn("DNS registration hook: no FQDNs derived for internal zone",
				slog.String("internal_domain", internalDomain),
				slog.String("client_ip", ctx.ClientIP))
			return nil
		}

		var firstErr error
		registered := 0
		for _, fqdn := range fqdns {
			logger.Info("Attempting DNS registration",
				slog.String("fqdn", fqdn),
				slog.String("ip", ctx.ClientIP),
				slog.String("internal_domain", internalDomain))

			// Register the DNS record using go-trusted-platform's DNS service
			if _, err := dnsService.Register(context.Background(), fqdn, ctx.ClientIP); err != nil {
				logger.Error("DNS registration failed",
					slog.String("fqdn", fqdn),
					slog.String("error", err.Error()))
				if firstErr == nil {
					firstErr = &WrappedError{Msg: fmt.Sprintf("failed to register DNS record for %s", fqdn), Err: err}
				}
				continue
			}
			registered++
			logger.Info("Registered DNS record for enrolled device",
				slog.String("fqdn", fqdn),
				slog.String("ip", ctx.ClientIP),
				slog.String("model", ctx.TCGData.ProductModel),
				slog.String("serial", ctx.TCGData.ProductSerial))
		}

		// Zone-qualified registration (reflect-only; additional to standard records).
		// Requires zone_subdomains to be enabled on the DNS service and a resolvable
		// device profile with a declared network zone.
		if profiles != nil {
			serial := strings.TrimSpace(ctx.TCGData.ProductSerial)
			if serial != "" {
				if profile, err := profiles.FindBySerial(ctx.Context, serial); err == nil && profile != nil {
					var networkZone string
					if postCfg := profile.GetPostEnrollmentNetworkConfig(); postCfg != nil && postCfg.Zone != "" {
						networkZone = postCfg.Zone
					} else if profile.Zone != "" {
						networkZone = profile.Zone
					}
					if networkZone != "" {
						for _, fqdn := range fqdns {
							host := extractHostFromFQDN(fqdn, internalDomain)
							if host == "" || dns.IsBMCName(host) {
								continue
							}
							if err := dnsService.RegisterWithNetworkZone(
								context.Background(), host, networkZone, ctx.ClientIP,
							); err != nil {
								logger.Warn("zone-qualified DNS registration failed",
									slog.String("host", host),
									slog.String("networkZone", networkZone),
									slog.String("ip", ctx.ClientIP),
									slog.String("error", err.Error()))
								// Best-effort: do not fail the hook for zone-subdomain errors.
							} else {
								logger.Info("Registered zone-qualified DNS record for enrolled device",
									slog.String("host", host),
									slog.String("networkZone", networkZone),
									slog.String("ip", ctx.ClientIP))
							}
						}
					}
				}
			}
		}

		logger.Info("DNS registration hook completed",
			slog.Int("fqdns_total", len(fqdns)),
			slog.Int("fqdns_registered", registered),
			slog.String("client_ip", ctx.ClientIP))

		// Surface the first failure to the caller so the order
		// finalization audit trail records the partial state. The
		// remaining records still got registered (best-effort), so the
		// operator gets resolvable names even if one entry collided.
		return firstErr
	}
}

// extractHostFromFQDN extracts the bare host label from an FQDN by stripping
// the internal domain suffix. Returns "" when the FQDN does not match the domain.
func extractHostFromFQDN(fqdn, internalDomain string) string {
	// Normalise: remove trailing dots for comparison.
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(internalDomain)), ".")
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	suffix := "." + domain
	if !strings.HasSuffix(name, suffix) {
		return ""
	}
	host := strings.TrimSuffix(name, suffix)
	// Only the first label (no further dots) is a plain host label.
	if strings.Contains(host, ".") {
		return ""
	}
	return host
}

// collectFQDNsForInternalZone derives the full set of DNS A-record
// FQDNs to publish for a successful enroll-01 finalization. Returns a
// deduplicated, lowercase slice — empty when no candidate fits the
// internal-domain zone (which itself only happens when both the TCG
// fields and the cert SANs land outside the zone).
func collectFQDNsForInternalZone(ctx *trustedca.ACMEOrderFinalizeHookContext, internalDomain string) []string {
	// Normalise the configured zone to a canonical comparator. DNS
	// zone names are typically supplied with a trailing dot
	// ("example.internal.") to make their root-anchored form
	// explicit, but the FQDNs we assemble from cert SANs/TCG data
	// are usually relative ("gw.example.internal"). Strip the
	// trailing dot AND any leading dot before reconstructing the
	// suffix so the HasSuffix check works regardless of which
	// canonical form the caller passes in.
	zoneSuffix := "." + strings.Trim(strings.ToLower(strings.TrimSpace(internalDomain)), ".")
	if zoneSuffix == "." {
		return nil
	}

	// Dedup is case-insensitive (DNS names are case-insensitive per
	// RFC 1035 §2.3.3) but the registered value preserves the
	// original case so callers — and tests — that check the
	// canonical form stay stable across refactors.
	seen := make(map[string]struct{})
	var out []string
	add := func(name string) {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		if name == "" || strings.HasPrefix(name, "*.") {
			return
		}
		lower := strings.ToLower(name)
		// Only register names that land inside the internal-domain
		// zone; cross-zone records (e.g., gw.example.com) belong to
		// the public zone managed elsewhere.
		if !strings.HasSuffix(lower, zoneSuffix) && lower != strings.TrimPrefix(zoneSuffix, ".") {
			return
		}
		if _, ok := seen[lower]; ok {
			return
		}
		seen[lower] = struct{}{}
		out = append(out, name)
	}

	// 1. Model-serial form (always tried; preserved for attestation
	//    correlation). TCG ProductModel/ProductSerial come from the
	//    device's TCG-CSR-IDevID and frequently contain whitespace,
	//    underscores, or other characters that aren't valid in DNS
	//    labels (per RFC 1035 §2.3.1, labels are LDH — letters,
	//    digits, hyphens). Sanitize before assembling so we publish
	//    a record name the resolver will actually accept.
	if ctx.TCGData != nil &&
		ctx.TCGData.ProductModel != "" &&
		ctx.TCGData.ProductSerial != "" {
		add(fmt.Sprintf("%s-%s.%s",
			sanitizeDNSLabel(ctx.TCGData.ProductModel),
			sanitizeDNSLabel(ctx.TCGData.ProductSerial),
			strings.TrimPrefix(zoneSuffix, ".")))
	}

	// 2. Cert SANs and CN that fall inside the internal zone.
	if ctx.Certificate != nil {
		for _, dnsName := range ctx.Certificate.DNSNames {
			add(dnsName)
		}
		add(ctx.Certificate.Subject.CommonName)
	}

	// 3. CSR SANs (covers the case where the cert was issued from a
	//    raw CSR rather than the platform-rendered template).
	if ctx.CSR != nil {
		for _, dnsName := range ctx.CSR.DNSNames {
			add(dnsName)
		}
		add(ctx.CSR.Subject.CommonName)
	}

	return out
}

// sanitizeDNSLabel collapses anything that isn't an RFC 1035 LDH
// character into a single hyphen and trims leading/trailing hyphens
// and dots so the result is a valid DNS label component. Empty input
// returns empty. Runs of disallowed characters compact to a single
// hyphen so "SuperMicro X10" → "SuperMicro-X10" rather than
// "SuperMicro--X10".
func sanitizeDNSLabel(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			// Collapse runs of disallowed chars into one hyphen.
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	out := b.String()
	// Trim trailing hyphens and dots; leading hyphens were already
	// suppressed by the b.Len() > 0 guard above.
	out = strings.TrimRight(out, "-.")
	return out
}

// NewSDNEnrollmentHookAdapter creates an order finalization hook that triggers
// SDN network transitions for enrolled devices. This hook is called by go-trusted-ca's
// generic hook system after successful order finalization.
//
// The CA has no knowledge of SDN - this hook is entirely defined within
// go-trusted-platform and registered with the CA's generic hook registry.
func NewSDNEnrollmentHookAdapter(hook *policy.SDNEnrollmentHook, logger *slog.Logger) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		logger.Info("SDN enrollment hook called",
			slog.Bool("is_tcg_csr", ctx.IsTCGCSR),
			slog.Bool("tcg_data_nil", ctx.TCGData == nil),
			slog.String("client_ip", ctx.ClientIP))

		// Only process SDN transitions for TCG enrollments (device enrollment via enroll-01)
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			logger.Info("Skipping SDN enrollment - not a TCG CSR enrollment")
			return nil
		}

		// Convert OrderFinalizeHookContext to EnrollmentEvent
		event := &policy.EnrollmentEvent{
			Context:        ctx.Context,
			Certificate:    ctx.Certificate,
			CertificatePEM: ctx.CertificatePEM,
			ClientIP:       ctx.ClientIP,
			IsTCGCSR:       ctx.IsTCGCSR,
		}

		// Populate TCG-specific fields if available
		if ctx.TCGData != nil {
			event.ProductModel = ctx.TCGData.ProductModel
			event.ProductSerial = ctx.TCGData.ProductSerial
			event.PermanentIdentifier = ctx.TCGData.PermanentIdentifier
		}

		// Delegate to the SDN enrollment hook
		if err := hook.OnEnrollmentComplete(event); err != nil {
			logger.Error("SDN enrollment hook failed",
				slog.String("error", err.Error()),
				slog.String("client_ip", ctx.ClientIP))
			return &WrappedError{Msg: "SDN enrollment hook failed", Err: err}
		}

		logger.Info("Successfully processed SDN enrollment transition",
			slog.String("client_ip", ctx.ClientIP),
			slog.String("model", ctx.TCGData.ProductModel),
			slog.String("serial", ctx.TCGData.ProductSerial))

		return nil
	}
}

// DNSRegistrar defines the minimal interface required for registering DNS records.
// This interface is satisfied by dns.Service and allows for easier testing with mocks.
type DNSRegistrar interface {
	Register(ctx context.Context, fqdn, ip string) (*dnsentities.Zone, error)
	// RegisterWithNetworkZone registers the host under <host>.<networkZone>.<domain>
	// when zone_subdomains is enabled. No-op when zone_subdomains is false.
	RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error
}

// TLSARegistrar provides TLSA record management for DANE auto-generation.
// This interface is satisfied by dns.Service and allows for easier testing with mocks.
type TLSARegistrar interface {
	// AddTLSARecord adds a TLSA record to the specified zone.
	AddTLSARecord(ctx context.Context, zoneName string, record *dnsentities.TLSARecord) error
}

// NewTLSAGenerationHook creates a post-issuance hook that auto-generates
// TLSA records for DANE certificate pinning. The hook extracts the
// SubjectPublicKeyInfo from the issued certificate, hashes it with SHA-256,
// and creates a TLSA record in the DNS zone.
//
// Parameters:
//   - dnsService: DNS service implementing TLSARegistrar for record management
//   - daneConfig: DANE configuration with default parameters
//   - zoneName: The DNS zone where TLSA records will be created
//   - logger: Logger for operation logging
func NewTLSAGenerationHook(
	dnsService TLSARegistrar,
	daneConfig *dns.DANEConfig,
	zoneName string,
	logger *slog.Logger,
) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		if ctx.Certificate == nil {
			logger.Debug("TLSA generation skipped - no certificate in context")
			return nil
		}

		// Extract the certificate's common name for the TLSA record hostname
		hostname := ctx.Certificate.Subject.CommonName
		if hostname == "" {
			// Fall back to first SAN if no CN
			if len(ctx.Certificate.DNSNames) > 0 {
				hostname = ctx.Certificate.DNSNames[0]
			} else {
				logger.Warn("TLSA generation skipped - no hostname found in certificate")
				return nil
			}
		}

		// Extract SubjectPublicKeyInfo (SPKI) from the certificate
		spkiDER, err := x509.MarshalPKIXPublicKey(ctx.Certificate.PublicKey)
		if err != nil {
			logger.Error("Failed to marshal SPKI for TLSA generation",
				slog.String("error", err.Error()),
				slog.String("hostname", hostname))
			return nil // Don't fail certificate issuance for TLSA errors
		}

		// Hash the SPKI with SHA-256 (MatchingType 1)
		hash := sha256.Sum256(spkiDER)
		hashHex := hex.EncodeToString(hash[:])

		// Get default port from config, default to 443 for HTTPS
		defaultPort := daneConfig.DefaultPort
		if defaultPort == 0 {
			defaultPort = 443
		}

		// Get default TTL from config, default to 3600 seconds
		defaultTTL := daneConfig.DefaultTTL
		if defaultTTL == 0 {
			defaultTTL = 3600
		}

		// Build TLSA record name: _<port>._tcp.<hostname>.
		tlsaName := fmt.Sprintf("_%d._tcp.%s", defaultPort, hostname)
		if !strings.HasSuffix(tlsaName, ".") {
			tlsaName += "."
		}

		// Get TLSA parameters from config with sensible defaults
		// Usage: 3 (DANE-EE), Selector: 1 (SPKI), MatchingType: 1 (SHA-256)
		usage := daneConfig.DefaultUsage
		if usage == 0 {
			usage = 3 // DANE-EE
		}
		selector := daneConfig.DefaultSelector
		if selector == 0 {
			selector = 1 // SubjectPublicKeyInfo
		}
		matchingType := daneConfig.DefaultMatchingType
		if matchingType == 0 {
			matchingType = 1 // SHA-256
		}

		// Create TLSA record
		tlsaRecord := &dnsentities.TLSARecord{
			Name:         tlsaName,
			Usage:        usage,
			Selector:     selector,
			MatchingType: matchingType,
			Data:         hashHex,
			TTL:          defaultTTL,
		}

		// Add TLSA record to DNS zone
		err = dnsService.AddTLSARecord(context.Background(), zoneName, tlsaRecord)
		if err != nil {
			logger.Error("Failed to add TLSA record",
				slog.String("error", err.Error()),
				slog.String("tlsaName", tlsaName),
				slog.String("zoneName", zoneName))
			return nil // Don't fail certificate issuance for TLSA errors
		}

		logger.Info("TLSA record generated for DANE",
			slog.String("tlsaName", tlsaName),
			slog.Uint64("usage", uint64(usage)),
			slog.Uint64("selector", uint64(selector)),
			slog.Uint64("matchingType", uint64(matchingType)),
			slog.Int("hashLength", len(hashHex)),
			slog.Uint64("ttl", uint64(defaultTTL)))

		return nil
	}
}

// XKMSSigner provides access to crypto.Signer instances for key attributes.
// This interface is satisfied by both xkms.Backend and platform.XKMS.
type XKMSSigner interface {
	Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error)
}

type RestHandlerRegistry interface {
	ACMERestService() trustedca.ACMERestServicer
	AttestationServiceServer() platformv1.AttestationServiceServer
	CAServiceServer() platformv1.CAServiceServer
	ComputeServiceServer() platformv1.ComputeServiceServer
	DeviceServiceServer() platformv1.DeviceServiceServer
	DeviceRestHandler() device.RestHandler
	DeviceBootHandler() device.BootHandler
	ConfigDeliveryHandler() configdelivery.RestHandler
	DeviceService() devicepkg.DeviceService
	DNSService() dns.DNSService
	DNSServiceServer() platformv1.DNSServiceServer
	EABServiceServer() platformv1.EABServiceServer
	EmbeddedAdapter() sdktransport.Adapter
	GatewayServiceServer() platformv1.GatewayServiceServer
	IAMClients() (restiam.IAMClient, restiam.PEPClient)
	IDevIDServiceServer() platformv1.IDevIDServiceServer
	InvitationServiceServer() platformv1.InvitationServiceServer
	JSONWebTokenHandler() jwt.TokenHandler
	PlatformTokenMiddleware() middleware.AuthMiddleware
	KMSSDKClients() (kmsclient.Client, cryptoclient.Client, dekclient.Client, secretsclient.Client)
	MTLSMiddleware() middleware.MTLSMiddleware
	OverlayServiceServer() platformv1.OverlayServiceServer
	PlatformRestRouter() *platform.PlatformRouter
	PXEServiceServer() platformv1.PXEServiceServer
	PXEWebhookEnabled() bool
	NTPServiceServer() platformv1.NTPServiceServer
	VPNServiceServer() platformv1.VPNServiceServer
	AppServiceServers() restapi.AppServiceServers
	RegistryService() grpcapi.RegistryService
	OCIDistBackend() restregistry.OCIDistBackend
	HealthRegistry() health.Registry
	AttestationEventReader() restattestation.EventReader
	AttestationReporting() *restattestation.Reporting
	AttestationVerdicts() restattestation.VerdictPoller
	GatewayControlPlane() (restgateway.GatewayStateStore, restgateway.DesiredConfigSource)
	GatewayVPNLeases() restgateway.VPNLeaseSink
	ResponseWriter() response.HttpWriter
	SDNService() platformv1.SDNServiceServer
	TenantServiceServer() platformv1.TenantServiceServer
	TPM() xkmssdk.TrustedPlatformModule
	TPMServiceServer() platformv1.TPMServiceServer
	VTPMService() vtpm.VTPMService
	WebAuthnRestService() webauthn.RestHandler
	DeviceTemplateService() devicepkg.DeviceTemplateService
	DeviceProfileService() devicepkg.DeviceProfileService
	SwitchService() device.SwitchServiceProvider
	TenantID() string
	AdminClaimRestHandler() *adminclaim.RestHandler
}

// ACMEServerConfig contains the configuration for the ACME server
type ACMEServerConfig struct {
	// Enabled indicates whether the ACME server is enabled
	Enabled bool
	// BaseRESTURI is the base URL for ACME endpoints (e.g., "https://acme.example.com")
	BaseRESTURI string
	// CAAIdentities are the CAA identities for this server
	CAAIdentities []string
	// ChallengeMap maps challenge types to their verifier functions
	ChallengeMap map[string]trustedca.ACMEChallengeVerifierFunc
	// ExternalAccountRequired indicates whether external account binding is required
	ExternalAccountRequired bool
	// InternalDomain is the internal DNS domain for device DNS registration
	InternalDomain string
	// TermsOfService is the URL to the terms of service
	TermsOfService string
}

// EnrollmentHookProfileService implements device.ProfileService by querying
// the SDNEnrollmentHook for pending activations and returning device profiles.
type EnrollmentHookProfileService struct {
	hook *policy.SDNEnrollmentHook
}

// NewEnrollmentHookProfileService creates a new profile service backed by the SDN enrollment hook.
func NewEnrollmentHookProfileService(hook *policy.SDNEnrollmentHook) *EnrollmentHookProfileService {
	return &EnrollmentHookProfileService{hook: hook}
}

// GetBySerial returns the device profile for a given serial number.
// It looks up the pending activation and converts the DeviceProfile to a ProfileResponse.
func (s *EnrollmentHookProfileService) GetBySerial(_ context.Context, serial string) (*device.ProfileResponse, error) {
	if s.hook == nil {
		return nil, device.ErrProfileServiceNotInitialized
	}

	pending, ok := s.hook.PeekPendingActivation(serial)
	if !ok || pending == nil || pending.Profile == nil {
		return nil, device.ErrProfileNotFoundBySerial
	}

	return device.ProfileFromDeviceProfile(pending.Profile, serial), nil
}

// ZoneProfileResolver resolves a DeviceProfile by device serial number for zone
// extension injection. This minimal interface is satisfied by DeviceProfileService.
type ZoneProfileResolver interface {
	FindBySerial(ctx context.Context, serial string) (*deviceentities.DeviceProfile, error)
}

// ErrPreSignZoneResolutionFailed is returned when the zone extension pre-sign hook
// cannot determine the network zone for a certificate and encode_zone_in_cert
// requires one. Wrapping the underlying cause preserves the errors.Is / errors.As chain.
type ErrPreSignZoneResolutionFailed struct {
	Serial string
	Cause  error
}

// Error implements the error interface.
func (e ErrPreSignZoneResolutionFailed) Error() string {
	return "sdn: zone extension pre-sign hook failed for serial " + e.Serial + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrPreSignZoneResolutionFailed) Unwrap() error { return e.Cause }

// ErrDeviceZoneUnresolvable is returned when a TCG-CSR-IDEVID (device)
// enrollment cannot resolve a network zone from the device profile while
// encode_zone_in_cert is enabled. Device enrollments fail closed: falling
// back to the platform zone would issue a device certificate carrying an
// operator-level zone (management by default), silently granting the device
// the wrong network placement.
type ErrDeviceZoneUnresolvable struct {
	Serial string
	Reason string
}

// Error implements the error interface.
func (e ErrDeviceZoneUnresolvable) Error() string {
	return "sdn: device zone unresolvable for serial " + e.Serial + " (" + e.Reason + "); refusing to issue zone-encoded device certificate"
}

// NewZoneExtensionPreSignHook returns an ACME OrderPreSignHook that embeds the
// OIDTPNetworkZone extension into every DEVICE certificate when
// sdn.identity.encode_zone_in_cert is true.
//
// Zone resolution for TCG-CSR-IDEVID (enroll-01) DEVICE enrollments:
//  1. DeviceProfile.GetPostEnrollmentNetworkConfig().Zone  (per-profile, per-phase)
//  2. DeviceProfile.Zone                                   (profile-level default)
//  3. FAIL CLOSED (ErrDeviceZoneUnresolvable) — a device whose zone cannot be
//     determined from its profile must not receive a zone-encoded certificate;
//     falling back to the platform zone would grant it operator-level network
//     placement (management by default).
//
// For standard CSR paths (non-TCG, e.g. service/server certificates) the
// operator-configured IdentityConfig.ResolvedPlatformZone() is used.
// Returns nil, nil when encode_zone_in_cert is false or the identity config is nil.
func NewZoneExtensionPreSignHook(
	profiles ZoneProfileResolver,
	identity *sdn.IdentityConfig,
	logger *slog.Logger,
) trustedca.ACMEOrderPreSignHook {
	return func(ctx *trustedca.ACMEOrderPreSignHookContext) ([]pkix.Extension, error) {
		if identity == nil || !identity.EncodeZoneInCert {
			return nil, nil
		}

		var zoneName, serial string

		if ctx.IsTCGCSR {
			// Device enrollment: the device profile is the only authoritative
			// zone source. Fail closed on any gap in the resolution chain.
			if ctx.TCGData == nil {
				return nil, ErrDeviceZoneUnresolvable{Reason: "no TCG data on enrollment"}
			}
			serial = strings.TrimSpace(ctx.TCGData.ProductSerial)
			if serial == "" {
				return nil, ErrDeviceZoneUnresolvable{Reason: "empty product serial"}
			}
			if profiles == nil {
				return nil, ErrDeviceZoneUnresolvable{Serial: serial, Reason: "no profile resolver configured"}
			}
			profile, err := profiles.FindBySerial(ctx.Context, serial)
			if err != nil || profile == nil {
				logger.Warn("zone extension pre-sign: device profile unresolvable, refusing zone-encoded issuance",
					slog.String("serial", serial))
				return nil, ErrDeviceZoneUnresolvable{Serial: serial, Reason: "device profile not found"}
			}
			if postCfg := profile.GetPostEnrollmentNetworkConfig(); postCfg != nil && postCfg.Zone != "" {
				zoneName = postCfg.Zone
			} else if profile.Zone != "" {
				zoneName = profile.Zone
			} else {
				return nil, ErrDeviceZoneUnresolvable{Serial: serial, Reason: "profile declares no zone"}
			}
		} else {
			// Non-device certificate: the operator-configured platform zone
			// applies (explicit config, not a guess about a device).
			zoneName = identity.ResolvedPlatformZone()
		}

		exts, err := sdn.BuildNetworkZoneExtensions(identity, zoneName, serial)
		if err != nil {
			logger.Warn("zone extension pre-sign hook failed",
				slog.String("serial", serial),
				slog.String("zone", zoneName),
				slog.String("error", err.Error()))
			return nil, ErrPreSignZoneResolutionFailed{Serial: serial, Cause: err}
		}

		if len(exts) > 0 {
			logger.Debug("zone extension pre-sign hook: embedding network zone",
				slog.String("serial", serial),
				slog.String("zone", zoneName),
				slog.Bool("is_tcg_csr", ctx.IsTCGCSR))
		}

		return exts, nil
	}
}

// RegistryParams holds all dependencies required to construct the handler registry.
// The UserTokenIssuer adapter must keep satisfying the platform
// service layer's TokenIssuer seam.
var _ service.TokenIssuer = (*jwt.UserTokenIssuer)(nil)

type RegistryParams struct {
	ACMEServerConfig         *ACMEServerConfig
	ACMEStorageFactory       trustedca.ACMEStorageFactory
	CA                       trustedca.CACertificateAuthority
	CAConfig                 *trustedca.CAConfig
	Debug                    bool
	DNSConfig                *dns.Config
	HTTPWriter               response.HttpWriter
	IAMClient                restiam.IAMClient
	XKMS                     XKMSSigner
	KMSClient                kmsclient.Client
	CryptoClient             cryptoclient.Client
	DEKClient                dekclient.Client
	SecretsClient            secretsclient.Client
	JWTAudience              string
	JWTClaimsIssuer          string
	JWTExpiration            int
	Logger                   *logging.Logger
	PEPClient                restiam.PEPClient
	AttestationServiceServer platformv1.AttestationServiceServer
	CAServiceServer          platformv1.CAServiceServer
	ComputeServiceServer     platformv1.ComputeServiceServer
	DNSServiceServer         platformv1.DNSServiceServer
	DeviceServiceServer      platformv1.DeviceServiceServer
	EABServiceServer         platformv1.EABServiceServer
	EmbeddedAdapter          sdktransport.Adapter
	GatewayServiceServer     platformv1.GatewayServiceServer
	IDevIDServiceServer      platformv1.IDevIDServiceServer
	InvitationServiceServer  platformv1.InvitationServiceServer
	OverlayServiceServer     platformv1.OverlayServiceServer
	PXEServiceServer         platformv1.PXEServiceServer
	// PXEWebhookEnabled is pxe.ServiceConfig.WebhookEnabled: it mounts the
	// unauthenticated POST /pxe/webhook/complete (#238). Nothing in the
	// daemon sets it today, so the route is not served.
	PXEWebhookEnabled bool
	NTPServiceServer  platformv1.NTPServiceServer
	VPNServiceServer  platformv1.VPNServiceServer
	// AppServiceServers are the daemon's Cache, Scheduler, Messaging and
	// ObjectStorage servers, the instances behind every other transport.
	AppServiceServers restapi.AppServiceServers
	SDNEnrollmentHook *policy.SDNEnrollmentHook
	// SDNIdentityConfig is sourced from app.SDNConfig.Identity. When present and
	// encode_zone_in_cert is true, the ACME pre-sign hook embeds the device's
	// network zone into every issued DEVICE certificate via OIDTPNetworkZone.
	SDNIdentityConfig   *sdn.IdentityConfig
	SDNService          platformv1.SDNServiceServer
	ServerKeyAttributes *xkmssdk.KeyAttributes
	ServiceRegistry     *service.Registry
	// PublicRegistrationEnabled mirrors the canonical
	// iam.self_service_registration.enabled flag (default false:
	// invite-only). It gates uninvited WebAuthn registration.
	PublicRegistrationEnabled bool
	// TenantManager enables tenant orchestration for WebAuthn
	// registration. The platform service registry is constructed before
	// the tenant manager exists, so the daemon passes the manager here
	// and WebAuthnRestService materializes the TenantUserService lazily
	// (Registry.SetTenantUserService is the documented late-wiring
	// seam). Nil leaves registration tenant-less, exactly as before.
	TenantManager *tenant.Manager
	// DBKeySigner backs the config delivery /provisioning/sign endpoint with
	// control-plane Secure Boot DB digest signing. Supplied by the platform
	// daemon (api/daemon.RemoteDBKeySigner); nil disables the sign endpoint.
	DBKeySigner     configdelivery.DBKeySigner
	ServicesManager platform.ServicesManager
	// ProtocolConfig is the bound protocol address/enabled snapshot used by
	// GET /api/v1/platform/protocols. When nil the handler returns 500.
	ProtocolConfig *platform.ProtocolConfig
	// VersionInfo populates the platform version/status responses. When nil
	// the handlers return empty version metadata.
	VersionInfo *platform.VersionInfo
	// HealthRegistry powers the platform health and metrics endpoints.
	HealthRegistry health.Registry
	// ConfigReloader wires /api/v1/platform/config/reload. When nil
	// the endpoint returns 503 with a structured "not configured"
	// envelope so callers can tell it apart from an actual reload
	// failure.
	ConfigReloader platform.ConfigReloader
	// LogQuerier wires /api/v1/platform/logs. When nil the endpoint
	// returns 503 with the same structured-honesty pattern.
	LogQuerier platform.LogQuerier
	// RegistryService wires /api/v1/compute/images. When nil the
	// /compute/images surface returns 503 via the service registry.
	RegistryService grpcapi.RegistryService
	// AttestationCapture, when set, receives a manifest capture for
	// every TCG-CSR enrollment that completes via enroll-01. The
	// captured manifests are surfaced by /api/v1/attestation/manifests.
	// Decoupled via the interface so registry.go doesn't import
	// pkg/attestation/service directly.
	AttestationCapture AttestationCaptureSvc
	// AttestationEventReader backs /api/v1/attestation/events. When
	// nil the surface returns 503.
	AttestationEventReader restattestation.EventReader
	// AttestationReporting carries the node's caller-admission policy for
	// the quote-producing attestation routes (#226). Nil on a node with
	// none, which leaves those routes operator-only.
	AttestationReporting *restattestation.Reporting
	// AttestationVerdicts backs /api/v1/attestation/verdicts, the device
	// verdict long-poll (#709). When nil the route answers 503.
	AttestationVerdicts restattestation.VerdictPoller
	// GatewayStateStore + GatewayDesiredConfig back /api/v1/gateway/*.
	// When both nil, control-plane routes are not registered.
	GatewayStateStore    restgateway.GatewayStateStore
	GatewayDesiredConfig restgateway.DesiredConfigSource
	// GatewayVPNLeases backs /api/v1/gateway/vpn-leases/*. When nil those
	// routes answer 500 ErrGatewayControlNotConfigured.
	GatewayVPNLeases restgateway.VPNLeaseSink
	// OCIDistBackend wires the spec-compliant /v2/ distribution
	// surface so `crane` / `skopeo` / `oras` can push and pull
	// against the registry directly. Set by the daemon boot path
	// alongside RegistryService — both point at the same *Registry.
	OCIDistBackend      restregistry.OCIDistBackend
	SwitchService       device.SwitchServiceProvider
	TenantServiceServer platformv1.TenantServiceServer
	TPMServiceServer    platformv1.TPMServiceServer
	TPM                 xkmssdk.TrustedPlatformModule
	VTPMService         vtpm.VTPMService
	WebServiceConfig    *Config
	WebAuthnConfig      *webauthn.Config
	// FIDO2SDKClient is the relying-party client the WebAuthn REST
	// handler delegates ceremony operations to. It is the SDK's single
	// canonical WebAuthn/FIDO2 ceremony surface. Required whenever
	// WebAuthnConfig is supplied; when nil the WebAuthn routes are
	// disabled.
	FIDO2SDKClient quicbaassdk.FIDO2Client
	// TenantID is the platform operating tenant (the firstboot system
	// tenant adopted by pkg/app). The WebAuthn handler scopes every SDK
	// ceremony call to it.
	TenantID string
	// AuthSDKClient is the quicbaas SDK unified login surface
	// (Security().Auth()), narrowed to the two ceremony verbs the
	// platform actually consumes. The SDK AuthService satisfies it
	// directly; every other capability that surface exposes reaches the
	// platform through its own param above, so widening this one would
	// only obscure what the login path depends on.
	//
	// When wired, every login route authenticates through the unified
	// ceremony and returns the session it issued. When nil the login
	// routes fail closed and the WebAuthn routes are not registered.
	AuthSDKClient login.UnifiedLoginClient
	// FactorsSDKClient is the SDK auth-factor surface
	// (Security().Auth().Factors()). The admin-claim ceremony reads it to
	// decide whether the system admin identity has already been claimed.
	// When nil the claim routes are not registered.
	FactorsSDKClient quicbaassdk.AuthFactorsClient
	// AdminTrustAnchorPath is the PEM bundle the firstboot admin
	// certificate must chain to — the QuicBaaS CA chain the embedded
	// server wrote beside the admin bundle
	// (<quicbaas data-dir>/certs/ca-chain.crt). Empty disables the
	// admin-claim routes: without an anchor no certificate can be
	// verified, and an unverifiable claim must not be offered.
	AdminTrustAnchorPath string
	// AdminEmail is the firstboot admin account's email — the identifier
	// the FIDO2 ceremony enrols against. Empty leaves the admin-claim
	// routes unregistered.
	AdminEmail string
	// AdminClaimMultiInstance reports that several platformd instances
	// serve one store. The admin-claim ceremony is refused when true —
	// its one-time state is process-local and SDK factor enrolment is
	// not conditional, so two instances could each enrol a different
	// authenticator for the same one-time ownership transfer. See #170.
	AdminClaimMultiInstance bool
}

type HandlerRegistry struct {
	jwtService              *jwt.Service
	loginDriver             *login.Driver
	platformTokenMiddleware *iammw.PlatformTokenMiddleware
	params                  RegistryParams
	RestHandlerRegistry
}

// LoginDriver returns the platform's single unified login driver, built
// once and shared by every login route.
//
// One driver exists because there is one ceremony: a factor contributes a
// binder, never a second copy of the Begin/Finish sequence. The mtls
// binder serves /login; the fido2 binder serves the WebAuthn routes.
//
// Returns nil when the SDK AuthService is unavailable — which makes every
// login route fail closed rather than authenticate anyone locally — or
// when no JWT signer exists to issue the session credential with.
func (registry *HandlerRegistry) LoginDriver() *login.Driver {
	if registry.loginDriver != nil {
		return registry.loginDriver
	}
	if registry.params.AuthSDKClient == nil {
		return nil
	}
	// The driver mints the session credential through the same signer the
	// inbound seam validates with, so without it a login could only return
	// a credential this server rejects. No signer, no login surface.
	if registry.jwtService == nil {
		return nil
	}
	// And the credential it mints is a platform-local JWT, which the BROKER
	// seam does not accept. Under that seam a completed login would hand
	// the operator a session every protected route rejects, so the login
	// surface is declined instead — exactly as AdminClaimRestHandler
	// declines the claim ceremony for the same reason. Converging the two
	// token types is #202; teaching the seam to accept both is explicitly
	// not the answer.
	if registry.brokerTokenSeamEnabled() {
		registry.params.Logger.Warn(
			"login routes not registered: JWT.PlatformToken.Enabled makes the " +
				"broker validator the inbound seam, which does not accept the " +
				"platform-minted session a login issues (#202)")
		return nil
	}
	binders := []login.Binder{login.NewMTLSBinder()}
	// The WebAuthn binder is tenant-scoped: an assertion is only valid
	// against the relying party of the tenant owning the credential, so
	// without an operating tenant the fido2 factor is simply not offered
	// rather than offered and broken. Its session lands in the user's own
	// workspace, which the tenant user service resolves (#662); without
	// that service the only tenant left is the operating one, which a
	// browser login never lands in, so the factor is not offered either.
	if tus := registry.tenantUserService(); registry.params.TenantID != "" && tus != nil {
		fido2, err := login.NewFIDO2Binder(registry.params.TenantID, tus)
		if err != nil {
			registry.params.Logger.FatalError(err)
		}
		binders = append(binders, fido2)
	}
	// A session landed in a workspace carries the principal's roles in
	// that workspace, read from its IAM tenant. Without an IAM client it
	// carries none (#662).
	var roles login.RoleResolver
	if registry.params.IAMClient != nil {
		resolver, err := restiam.NewWorkspaceRoleResolver(registry.params.IAMClient)
		if err != nil {
			registry.params.Logger.FatalError(err)
		}
		roles = resolver
	}
	driver, err := login.NewDriver(login.DriverParams{
		Client:         registry.params.AuthSDKClient,
		Binders:        binders,
		SessionIssuer:  registry.jwtService,
		Roles:          roles,
		Logger:         registry.params.Logger,
		ResponseWriter: registry.params.HTTPWriter,
	})
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	registry.loginDriver = driver
	return driver
}

// tenantUserService returns the platform's tenant user service, building
// it on first use.
//
// The platform service registry is built before the tenant manager exists
// (NewRegistry passes TenantManager: nil), so on the daemon path the
// registry holds none even though tenant orchestration is fully available.
// It is materialized here: the JWT service signs the tenant-scoped token
// through the UserTokenIssuer adapter, and the service is pushed back into
// the platform registry so every other consumer observes the same
// instance. It returns nil when a dependency is missing.
func (registry *HandlerRegistry) tenantUserService() service.TenantUserServicer {
	tus := registry.params.ServiceRegistry.TenantUserService()
	if tus != nil || registry.params.TenantManager == nil {
		return tus
	}
	userSvc := registry.params.ServiceRegistry.UserService()
	invitationSvc := registry.params.ServiceRegistry.InvitationService()
	if userSvc == nil || invitationSvc == nil || registry.jwtService == nil {
		return nil
	}
	issuer, err := jwt.NewUserTokenIssuer(userSvc, registry.jwtService)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	tus = service.NewTenantUserService(&service.TenantUserServiceConfig{
		Logger:            registry.params.Logger,
		UserService:       userSvc,
		InvitationService: invitationSvc,
		TenantManager:     registry.params.TenantManager,
		TokenIssuer:       issuer,
	})
	registry.params.ServiceRegistry.SetTenantUserService(tus)
	registry.params.Logger.Info("tenant user service wired for WebAuthn registration and login")
	return tus
}

// JWTService returns the underlying JWT service so callers (notably the
// daemon's gRPC/QUIC auth interceptors) can verify tokens minted by the
// webserver's /api/v1/login endpoint.
func (registry *HandlerRegistry) JWTService() *jwt.Service {
	if registry == nil {
		return nil
	}
	return registry.jwtService
}

func NewHandlerRegistry(ctx context.Context, params RegistryParams) RestHandlerRegistry {
	jwtParams := jwt.ServiceParams{
		Audience:   params.JWTAudience,
		Expiration: params.JWTExpiration,
		Issuer:     params.JWTClaimsIssuer,
		KeyAttrs:   params.ServerKeyAttributes,
		XKMS:       params.XKMS,
	}
	jwtService, err := jwt.NewService(ctx, jwtParams)
	if err != nil {
		params.Logger.FatalError(err)
	}
	return &HandlerRegistry{
		jwtService: jwtService,
		params:     params,
	}
}

func (registry *HandlerRegistry) JSONWebTokenHandler() jwt.TokenHandler {
	handler, err := jwt.NewRestHandler(
		registry.params.Logger,
		registry.params.HTTPWriter,
		registry.jwtService,
		registry.params.ServiceRegistry.UserService())
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	// Wire the unified login driver so /login authenticates through the
	// canonical ceremony and returns the session it issued. When the SDK
	// AuthService is unavailable the handler fails closed rather than
	// minting an unverified local JWT.
	if driver := registry.LoginDriver(); driver != nil {
		if rh, ok := handler.(*jwt.RestHandler); ok {
			rh.SetLoginDriver(driver)
		}
	}
	return handler
}

// brokerTokenSeamEnabled reports whether the inbound authentication seam is
// the broker platform-token validator rather than the platform-local JWT
// handler. It answers from configuration alone, so callers that only need
// to know WHICH seam is in force never build the validator (or its JWKS
// client) as a side effect.
func (registry *HandlerRegistry) brokerTokenSeamEnabled() bool {
	cfg := registry.params.WebServiceConfig
	return cfg != nil && cfg.JWT.PlatformToken.Enabled
}

// PlatformTokenMiddleware returns the broker platform-token validator
// middleware when JWT.PlatformToken.Enabled is set in the webservice config,
// or nil otherwise. It is the pure-validator inbound auth path: the platform
// validates broker-issued, JWKS-published, DPoP-bound access tokens (iss/aud/
// exp + cnf.jkt) and maps scp -> RBAC + tenant_id -> RLS, instead of locally
// minted JWTs. The validator (and its JWKS cache) is built once and reused.
//
// Returning middleware.AuthMiddleware lets it slot into the same router auth
// seam as the legacy JWT handler. The build fails closed: a configured-but-
// invalid broker validator aborts startup rather than silently disabling auth.
func (registry *HandlerRegistry) PlatformTokenMiddleware() middleware.AuthMiddleware {
	if !registry.brokerTokenSeamEnabled() {
		return nil
	}
	cfg := registry.params.WebServiceConfig
	if registry.platformTokenMiddleware != nil {
		return registry.platformTokenMiddleware
	}

	pt := cfg.JWT.PlatformToken
	validator, err := iammw.NewPlatformTokenValidator(iammw.PlatformTokenValidatorParams{
		Issuer:                    pt.Issuer,
		JWKSURL:                   pt.JWKSURL,
		Audience:                  pt.Audience,
		CacheTTL:                  time.Duration(pt.CacheTTLSeconds) * time.Second,
		IntrospectionURL:          pt.IntrospectionURL,
		IntrospectionClientID:     pt.IntrospectionClientID,
		IntrospectionClientSecret: pt.IntrospectionClientSecret,
		IntrospectionBearerToken:  pt.IntrospectionBearerToken,
		AuthzMode:                 pt.AuthzMode,
		LivenessCacheTTL:          time.Duration(pt.LivenessCacheTTLSeconds) * time.Second,
	})
	if err != nil {
		registry.params.Logger.FatalError(err)
	}

	mw, err := iammw.NewPlatformTokenMiddleware(
		registry.params.Logger,
		registry.params.HTTPWriter,
		validator,
		iammw.PlatformTokenConfig{AllowBearer: pt.AllowBearer},
	)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	registry.platformTokenMiddleware = mw
	return mw
}

// KMSSDKClients returns the four QuicBaaS SDK clients used by the KMS
// REST router. Per project convention these are go-quicbaas SDK
// interfaces, never raw gRPC client interfaces.
func (registry *HandlerRegistry) KMSSDKClients() (kmsclient.Client, cryptoclient.Client, dekclient.Client, secretsclient.Client) {
	return registry.params.KMSClient, registry.params.CryptoClient, registry.params.DEKClient, registry.params.SecretsClient
}

func (registry *HandlerRegistry) IAMClients() (restiam.IAMClient, restiam.PEPClient) {
	return registry.params.IAMClient, registry.params.PEPClient
}

func (registry *HandlerRegistry) SystemRestService() system.RestHandler {
	return system.NewHandler(
		registry.params.CA,
		registry.params.CAConfig,
		registry.params.ServerKeyAttributes,
		registry.params.HTTPWriter,
		registry.params.Logger,
		registry.params.TPM)
}

func (registry *HandlerRegistry) TPM() xkmssdk.TrustedPlatformModule {
	return registry.params.TPM
}

func (registry *HandlerRegistry) VTPMService() vtpm.VTPMService {
	return registry.params.VTPMService
}

func (registry *HandlerRegistry) ResponseWriter() response.HttpWriter {
	return registry.params.HTTPWriter
}

func (registry *HandlerRegistry) SDNService() platformv1.SDNServiceServer {
	return registry.params.SDNService
}

// WebAuthnRestService returns the WebAuthn REST handler, or nil if
// WebAuthn is not configured or no SDK client or tenant user service is
// wired. Callers must check for nil before using the handler.
func (registry *HandlerRegistry) WebAuthnRestService() webauthn.RestHandler {
	if !webauthn.IsConfigured(registry.params.WebAuthnConfig) {
		registry.params.Logger.Warn("WebAuthn not configured, WebAuthn routes will not be registered")
		return nil
	}
	if registry.params.FIDO2SDKClient == nil {
		registry.params.Logger.Warn("WebAuthn SDK client not wired, WebAuthn routes will not be registered")
		return nil
	}
	// The login verbs run entirely on the unified driver, so without one
	// the routes are not registered rather than registered and unable to
	// authenticate. This mirrors how every other unavailable seam is
	// handled here: decline the surface, never serve a broken one.
	loginDriver := registry.LoginDriver()
	if loginDriver == nil {
		registry.params.Logger.Warn("unified login driver not wired, WebAuthn routes will not be registered")
		return nil
	}
	// Registration creates the user's workspace and mints its session
	// there through the tenant user service. Without one the only tenant
	// left for that session is the operating one, which a browser session
	// never lands in (#662), so the surface is declined — as the login
	// driver declines its fido2 factor for the same reason.
	tus := registry.tenantUserService()
	if tus == nil {
		registry.params.Logger.Warn("tenant user service not wired, WebAuthn routes will not be registered")
		return nil
	}
	// Wire the QuicBaaS IAM mirror so RegisterNewUser surfaces the
	// freshly-registered user into /api/v1/iam/users. The mirror is
	// constructed lazily here because TenantUserService is built at
	// service-registry construction time, before the IAM client is
	// available, and the cleanest decoupling is "the IAM REST adapter
	// owns the mirror; the platform service receives it via setter."
	if registry.params.IAMClient != nil {
		mirror := restiam.NewQuicBaaSUserMirror(registry.params.IAMClient)
		tus.SetIAMMirror(mirror)
		registry.startIAMUserReconcile(mirror)
	}
	params := webauthn.ServiceParams{
		Config:                    registry.params.WebAuthnConfig,
		Debug:                     registry.params.Debug,
		Logger:                    registry.params.Logger,
		RegistrationService:       registry.params.ServiceRegistry.RegistrationService(),
		ResponseWriter:            registry.params.HTTPWriter,
		SessionService:            registry.params.ServiceRegistry.WebAuthnSessionService(),
		UserService:               registry.params.ServiceRegistry.UserService(),
		TenantUserService:         tus,
		InvitationService:         registry.params.ServiceRegistry.InvitationService(),
		FIDO2Client:               registry.params.FIDO2SDKClient,
		LoginDriver:               loginDriver,
		TenantID:                  registry.params.TenantID,
		PublicRegistrationEnabled: registry.params.PublicRegistrationEnabled,
	}
	handler, err := webauthn.NewHandler(params)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}

// iamReconcileTimeout bounds the startup IAM user reconcile.
const iamReconcileTimeout = 5 * time.Minute

// startIAMUserReconcile mirrors the platform users missing from their IAM
// tenant (#641) in the background, so a slow IAM backend never delays
// startup. It returns a channel closed when the run finishes, or nil when the
// run was not started.
func (registry *HandlerRegistry) startIAMUserReconcile(mirror *restiam.QuicBaaSUserMirror) <-chan struct{} {
	if registry.params.TenantManager == nil {
		registry.params.Logger.Warn("tenant manager not wired, IAM user reconcile not started")
		return nil
	}
	reconciler, err := registry.params.ServiceRegistry.IAMUserReconciler(mirror, mirror, registry.params.TenantManager)
	if err != nil {
		registry.params.Logger.Warn("IAM user reconcile not started", "error", err)
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		registry.reconcileIAMUsers(reconciler)
	}()
	return done
}

// reconcileIAMUsers runs one IAM user reconcile and logs its report.
func (registry *HandlerRegistry) reconcileIAMUsers(reconciler *service.IAMUserReconciler) {
	ctx, cancel := context.WithTimeout(context.Background(), iamReconcileTimeout)
	defer cancel()
	report, err := reconciler.Reconcile(ctx)
	if err != nil {
		registry.params.Logger.Warn("IAM user reconcile failed", "error", err)
		return
	}
	registry.params.Logger.Info("IAM user reconcile finished",
		"scanned", report.Scanned,
		"skipped", report.Skipped,
		"present", report.Present,
		"mirrored", report.Mirrored,
		"failed", report.Failed)
}

// AdminClaimRestHandler returns the platform-admin claim ceremony handler,
// or nil when the deployment cannot support the ceremony (no SDK ceremony
// client, no factor client, no trust anchor, no operating tenant, or an
// inbound auth seam that cannot validate the session the ceremony mints).
//
// Returning nil leaves the routes unregistered. That is the fail-closed
// direction: the ceremony's only protection is the certificate proof, so a
// deployment that cannot verify a certificate must not publish it.
func (registry *HandlerRegistry) AdminClaimRestHandler() *adminclaim.RestHandler {
	params := registry.params
	// Checked before any dependency, because it is a property of the
	// deployment rather than of the wiring. The ceremony completes by
	// minting a platform-local JWT; when the inbound seam is the broker
	// platform-token validator it accepts only broker-issued bearers, so
	// that session could not call a single protected route — the ceremony
	// would hand the operator a credential the same server rejects. Not
	// offering the flow is the fail-closed answer. Converging the two token
	// types is #202 (owner ruling 2026-09-02), which retires the local
	// issuer rather than teaching the seam to accept both.
	if registry.brokerTokenSeamEnabled() {
		params.Logger.Warn(
			"admin-claim routes not registered: JWT.PlatformToken.Enabled makes the " +
				"broker validator the inbound seam, which cannot validate the " +
				"platform JWT this ceremony issues (see issue #202)")
		return nil
	}
	if params.FIDO2SDKClient == nil || params.FactorsSDKClient == nil {
		params.Logger.Debug("admin-claim routes not registered: SDK auth clients are not wired")
		return nil
	}
	if params.AdminTrustAnchorPath == "" {
		params.Logger.Debug("admin-claim routes not registered: no admin trust anchor configured")
		return nil
	}
	if params.ServiceRegistry == nil {
		params.Logger.Debug("admin-claim routes not registered: no platform service registry")
		return nil
	}
	anchors, err := adminclaim.LoadTrustAnchor(params.AdminTrustAnchorPath)
	if err != nil {
		params.Logger.Error(err, "admin-claim routes not registered")
		return nil
	}
	svc, err := adminclaim.NewService(adminclaim.ServiceParams{
		Logger:        params.Logger,
		Ceremony:      params.FIDO2SDKClient,
		Factors:       params.FactorsSDKClient,
		Users:         params.ServiceRegistry.UserService(),
		TokenIssuer:   registry.jwtService,
		TrustAnchors:  anchors,
		TenantID:      params.TenantID,
		AdminUsername: common.AdminUsername,
		AdminEmail:    params.AdminEmail,
		MultiInstance: params.AdminClaimMultiInstance,
	})
	if err != nil {
		params.Logger.Error(err, "admin-claim routes not registered")
		return nil
	}
	handler, err := adminclaim.NewRestHandler(params.Logger, params.HTTPWriter, svc)
	if err != nil {
		params.Logger.Error(err, "admin-claim routes not registered")
		return nil
	}
	return handler
}

// DeviceRestHandler returns the PXE device activation REST handler.
// When a SwitchService is configured, it is injected into the handler so
// that Activate can move the device's physical port to the admitted VLAN.
func (registry *HandlerRegistry) DeviceRestHandler() device.RestHandler {
	// The heartbeat route records liveness through the platform device
	// service; without it the route responds with the typed
	// not-configured error instead of silently dropping reports.
	var opts []device.HandlerOption
	heartbeatWired := false
	if registry.params.ServiceRegistry != nil {
		if devSvc := registry.params.ServiceRegistry.DeviceService(); devSvc != nil {
			opts = append(opts, device.WithHeartbeatRecorder(devSvc))
			heartbeatWired = true
		}
	}
	// The mTLS device routes are registered when EITHER surface has a
	// backing implementation: heartbeat needs only the device service,
	// so a deployment without SDN enrollment still gets liveness — the
	// activation/profile routes then answer the typed not-configured
	// error rather than the whole device surface disappearing.
	if registry.params.SDNEnrollmentHook == nil && !heartbeatWired {
		registry.params.Logger.Debug("neither SDN enrollment hook nor device service available - device routes not registered")
		return nil
	}
	if registry.params.SwitchService != nil {
		opts = append(opts, device.WithSwitchService(registry.params.SwitchService))
	}
	// The enrollment hook is the single implementation of device activation:
	// port resolution (deferred to the device MAC when enrollment happened
	// off-fabric), policy application, and the authorized transition.
	var activator device.DeviceActivator
	var profileService device.ProfileService
	if registry.params.SDNEnrollmentHook != nil {
		activator = registry.params.SDNEnrollmentHook
		// The profile service queries pending activations on the hook.
		profileService = NewEnrollmentHookProfileService(registry.params.SDNEnrollmentHook)
	}
	return device.NewHandler(
		registry.params.Logger,
		registry.params.HTTPWriter,
		activator,
		profileService,
		opts...,
	)
}

// DeviceBootHandler returns the handler for a diskless node's per-boot
// routes (#690), or nil when the device service, profile service, quote
// verifier or CA is missing — the routes are then not registered.
func (registry *HandlerRegistry) DeviceBootHandler() device.BootHandler {
	if registry.params.ServiceRegistry == nil || registry.params.DeviceServiceServer == nil || registry.params.CA == nil {
		return nil
	}
	devices := registry.params.ServiceRegistry.DeviceService()
	profiles := registry.params.ServiceRegistry.ProfileService()
	if devices == nil || profiles == nil {
		return nil
	}
	return device.NewBootHandler(
		registry.params.Logger,
		registry.params.HTTPWriter,
		device.NewBootService(devices, profiles, registry.params.DeviceServiceServer, registry.params.CA),
	)
}

// ConfigDeliveryHandler returns a REST handler for pre-enrollment config
// delivery. This creates an in-memory service with a nonce store for devices
// to fetch their platform configuration at boot time.
// ProfileService and EABService are wired in when available -- nonce and session
// endpoints work even without them for the interactive QR provisioning flow.
func (registry *HandlerRegistry) ConfigDeliveryHandler() configdelivery.RestHandler {
	cdParams := configdelivery.ServiceParams{
		Logger: registry.params.Logger,
	}
	// Resolve the device profile service and EAB credential service from the
	// platform service registry so paradigm-B config delivery resolves real
	// configs by EK serial / MAC, enforces External Account Binding, and binds
	// the delivered config to the device's hardware EK certificate. The concrete
	// *device.ProfileService satisfies configdelivery.ProfileResolver
	// (FindConfigForDevice + Get); EK matching defaults to enforced.
	if registry.params.ServiceRegistry != nil {
		if ps := registry.params.ServiceRegistry.ProfileService(); ps != nil {
			cdParams.ProfileService = ps
		}
		cdParams.EABService = registry.params.ServiceRegistry.EABService()
	}
	if cfg := registry.params.WebServiceConfig; cfg != nil {
		cdParams.BaseURL = configdelivery.ProvisionBaseURL(cfg.Certificate.Subject.CommonName, cfg.TLSPort)
	}
	// Wire the daemon-supplied control-plane DB signer so the webservice's
	// config delivery handler can serve POST /api/v1/provisioning/sign.
	cdParams.DBKeySigner = registry.params.DBKeySigner
	svc, err := configdelivery.NewService(cdParams)
	if err != nil {
		registry.params.Logger.Warn("config delivery handler unavailable", "error", err)
		return nil
	}
	handler, err := configdelivery.NewHandler(configdelivery.HandlerParams{
		Service:        svc,
		ResponseWriter: registry.params.HTTPWriter,
		Logger:         registry.params.Logger,
	})
	if err != nil {
		registry.params.Logger.Warn("config delivery handler creation failed", "error", err)
		return nil
	}
	return handler
}

// DeviceTemplateService returns the device template service from the service registry.
func (registry *HandlerRegistry) DeviceTemplateService() devicepkg.DeviceTemplateService {
	if registry.params.ServiceRegistry == nil {
		return nil
	}
	templateService := registry.params.ServiceRegistry.TemplateService()
	if templateService == nil {
		return nil
	}
	return templateService
}

// DeviceProfileService returns the device profile service from the service registry.
func (registry *HandlerRegistry) DeviceProfileService() devicepkg.DeviceProfileService {
	if registry.params.ServiceRegistry == nil {
		return nil
	}
	profileService := registry.params.ServiceRegistry.ProfileService()
	if profileService == nil {
		return nil
	}
	return profileService
}
func (registry *HandlerRegistry) MTLSMiddleware() middleware.MTLSMiddleware {
	// Get the CA bundle PEM (root + intermediate certs) to build the
	// trusted cert pool. CABundle with zero-value filters returns the
	// full chain and handles nil trustedCA (per-CA keystore factories).
	bundlePEM, err := registry.params.CA.CABundle()
	if err != nil {
		registry.params.Logger.FatalError(&WrappedError{Msg: "failed to get CA bundle", Err: err})
	}

	trustedRoots := x509.NewCertPool()
	if !trustedRoots.AppendCertsFromPEM(bundlePEM) {
		registry.params.Logger.FatalError(&MessageError{Msg: "failed to parse CA bundle PEM"})
	}

	return middleware.NewMTLSMiddleware(
		registry.params.Logger,
		registry.params.HTTPWriter,
		trustedRoots,
	)
}

func (registry *HandlerRegistry) ACMERestService() trustedca.ACMERestServicer {
	if registry.params.ACMEServerConfig == nil || !registry.params.ACMEServerConfig.Enabled {
		registry.params.Logger.Warn("ACME service disabled")
		return nil
	}

	// Create order finalize hook registry for enrollment hooks
	hookRegistry := trustedca.NewACMEOrderFinalizeHookRegistry()

	// Register attestation import hook - this must run before DNS registration
	// to capture device attestation data during enrollment
	if registry.params.CA != nil {
		attestationHook := NewAttestationImportHook(
			registry.params.CA,
			registry.params.Logger.Slog())
		hookRegistry.Register(attestationHook)
		registry.params.Logger.Info("Registered attestation import hook for ACME device enrollment")
	} else {
		registry.params.Logger.Warn("CA is nil - attestation import hook not registered")
	}

	// Register attestation MANIFEST capture hook — distinct from the
	// CA import hook above. The CA hook stores raw evidence blobs in
	// the CA's per-device attestation store (used at policy time);
	// this hook turns the same evidence into a HostManifest for the
	// /api/v1/attestation/manifests surface. Both run on every TCG
	// CSR finalize.
	if registry.params.AttestationCapture != nil {
		manifestHook := NewAttestationManifestCaptureHook(
			registry.params.AttestationCapture,
			registry.params.Logger.Slog())
		hookRegistry.Register(manifestHook)
		registry.params.Logger.Info("Registered attestation manifest capture hook for ACME device enrollment")
	}

	// Register device-registration hook so each enrolled device shows
	// up in the platform's device inventory. The CA persists the
	// certificate; without this hook the WebUI Devices page and
	// dashboard counters stay empty even when enroll-01 succeeds.
	if deviceService := registry.params.ServiceRegistry.DeviceService(); deviceService != nil {
		deviceHook := NewDeviceRegistrationHook(deviceService, registry.params.Logger.Slog())
		hookRegistry.Register(deviceHook)
		registry.params.Logger.Info("Registered device registration hook for ACME device enrollment")
	} else {
		registry.params.Logger.Warn("Device service is nil - device registration hook not registered")
	}

	// Register DNS hook if DNS service is available
	// This hook is defined entirely within go-trusted-platform - the CA has no knowledge of DNS
	dnsService := registry.params.ServiceRegistry.DNSService()
	switch {
	case dnsService == nil:
		registry.params.Logger.Warn("DNS service is nil - DNS registration hook not registered")
	case registry.params.ACMEServerConfig.InternalDomain == "":
		registry.params.Logger.Warn("InternalDomain is empty - DNS registration hook not registered")
	default:
		var dnsProfileResolver ZoneProfileResolver
		if registry.params.ServiceRegistry != nil {
			dnsProfileResolver = registry.params.ServiceRegistry.ProfileService()
		}
		dnsHook := NewDNSRegistrationHook(
			dnsService,
			registry.params.ACMEServerConfig.InternalDomain,
			registry.params.Logger.Slog(),
			dnsProfileResolver)
		hookRegistry.Register(dnsHook)
		registry.params.Logger.Info("Registered DNS hook for ACME device enrollment",
			"internal_domain", registry.params.ACMEServerConfig.InternalDomain)
	}

	// Register SDN enrollment hook if available
	// This hook is defined entirely within go-trusted-platform - the CA has no knowledge of SDN
	if registry.params.SDNEnrollmentHook != nil {
		sdnHook := NewSDNEnrollmentHookAdapter(
			registry.params.SDNEnrollmentHook,
			registry.params.Logger.Slog())
		hookRegistry.Register(sdnHook)
		registry.params.Logger.Info("Registered SDN enrollment hook for ACME device enrollment")
	} else {
		registry.params.Logger.Debug("SDN enrollment hook is nil - SDN network transitions not enabled")
	}

	// Register TLSA generation hook for DANE auto-generation
	// This hook creates TLSA records in DNS for DANE certificate pinning after certificate issuance
	if dnsService != nil && registry.params.DNSConfig != nil && registry.params.DNSConfig.DANE != nil {
		daneConfig := registry.params.DNSConfig.DANE
		if daneConfig.Enabled && daneConfig.AutoGenerate {
			// Determine which zone to use for TLSA records
			var zoneName string
			if registry.params.DNSConfig.InternalServer != nil {
				zoneName = registry.params.DNSConfig.InternalServer.Zone.Name
			} else if registry.params.DNSConfig.PublicServer != nil {
				zoneName = registry.params.DNSConfig.PublicServer.Zone.Name
			}

			if zoneName != "" {
				tlsaHook := NewTLSAGenerationHook(
					dnsService,
					daneConfig,
					zoneName,
					registry.params.Logger.Slog(),
				)
				hookRegistry.Register(tlsaHook)
				registry.params.Logger.Info("Registered TLSA generation hook for DANE",
					"zoneName", zoneName,
					"defaultPort", daneConfig.DefaultPort,
					"defaultTTL", daneConfig.DefaultTTL)
			} else {
				registry.params.Logger.Warn("TLSA generation hook not registered - no zone configured")
			}
		} else {
			registry.params.Logger.Debug("DANE TLSA auto-generation disabled in configuration")
		}
	} else {
		registry.params.Logger.Debug("TLSA generation hook not registered - DNS service or DANE config unavailable")
	}

	// Build the pre-sign extension hook registry and register the zone extension
	// hook when SDN identity zone encoding is configured.
	preSignRegistry := trustedca.NewACMEOrderPreSignHookRegistry()
	if registry.params.SDNIdentityConfig != nil && registry.params.SDNIdentityConfig.EncodeZoneInCert {
		var profileResolver ZoneProfileResolver
		if registry.params.ServiceRegistry != nil {
			profileResolver = registry.params.ServiceRegistry.ProfileService()
		}
		zoneHook := NewZoneExtensionPreSignHook(
			profileResolver,
			registry.params.SDNIdentityConfig,
			registry.params.Logger.Slog(),
		)
		preSignRegistry.Register(zoneHook)
		registry.params.Logger.Info("Registered zone extension pre-sign hook for ACME device enrollment",
			"platform_zone", registry.params.SDNIdentityConfig.ResolvedPlatformZone())
	} else {
		registry.params.Logger.Debug("Zone extension pre-sign hook not registered - encode_zone_in_cert disabled or SDN identity config absent")
	}

	params := &trustedca.ACMERestServiceParams{
		BaseRESTURI:             registry.params.ACMEServerConfig.BaseRESTURI,
		CA:                      registry.params.CA,
		CAAIdentities:           registry.params.ACMEServerConfig.CAAIdentities,
		ChallengeMap:            registry.params.ACMEServerConfig.ChallengeMap,
		ExternalAccountRequired: registry.params.ACMEServerConfig.ExternalAccountRequired,
		Logger:                  registry.params.Logger.Slog(),
		OrderFinalizeHooks:      hookRegistry,
		OrderPreSignHooks:       preSignRegistry,
		StorageFactory:          registry.params.ACMEStorageFactory,
		TermsOfService:          registry.params.ACMEServerConfig.TermsOfService,
	}
	handler, err := trustedca.NewACMERestService(params)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}

func (registry *HandlerRegistry) PlatformRestRouter() *platform.PlatformRouter {
	router := platform.NewPlatformRouter(
		registry.params.Logger,
		registry.params.HTTPWriter,
	)
	if registry.params.ServicesManager != nil {
		router.SetServicesManager(registry.params.ServicesManager)
	}
	if registry.params.ProtocolConfig != nil {
		router.SetProtocolConfig(registry.params.ProtocolConfig)
	}
	if registry.params.VersionInfo != nil {
		router.SetVersionInfo(registry.params.VersionInfo)
	}
	if registry.params.HealthRegistry != nil {
		router.SetHealthRegistry(registry.params.HealthRegistry)
	}
	if registry.params.ConfigReloader != nil {
		router.SetConfigReloader(registry.params.ConfigReloader)
	}
	if registry.params.LogQuerier != nil {
		router.SetLogQuerier(registry.params.LogQuerier)
	}
	return router
}

// SwitchService returns the physical switch service provider from the registry params.
func (registry *HandlerRegistry) SwitchService() device.SwitchServiceProvider {
	return registry.params.SwitchService
}

// TenantID returns the platform's operating tenant — the firstboot system
// tenant adopted by pkg/app. It is the control-plane tenant the IAM
// router's system-tenant guard admits.
func (registry *HandlerRegistry) TenantID() string {
	return registry.params.TenantID
}

// DNSService returns the DNS service from the platform service registry,
// or nil when no DNS service is configured. The REST router gates the /dns
// surface on it; the routes themselves call DNSServiceServer.
func (registry *HandlerRegistry) DNSService() dns.DNSService {
	if registry.params.ServiceRegistry == nil {
		return nil
	}
	svc := registry.params.ServiceRegistry.DNSService()
	if svc == nil {
		return nil
	}
	return svc
}

// DeviceService returns the device service from the platform service registry,
// or nil when no device service is configured. The returned value satisfies
// the devicepkg.DeviceService interface used by the REST CRUD handler.
func (registry *HandlerRegistry) DeviceService() devicepkg.DeviceService {
	if registry.params.ServiceRegistry == nil {
		return nil
	}
	svc := registry.params.ServiceRegistry.DeviceService()
	if svc == nil {
		return nil
	}
	return svc
}

// EmbeddedAdapter returns the in-process sdk/go transport adapter used by REST
// routers to invoke daemon gRPC service implementations through their sdk/go
// service clients. Returns nil when no adapter has been configured.
func (registry *HandlerRegistry) EmbeddedAdapter() sdktransport.Adapter {
	return registry.params.EmbeddedAdapter
}

// AttestationServiceServer returns the in-process AttestationService gRPC
// implementation used by the REST attestation router, or nil when the
// service is not configured on this daemon.
func (registry *HandlerRegistry) AttestationServiceServer() platformv1.AttestationServiceServer {
	return registry.params.AttestationServiceServer
}

// DeviceServiceServer returns the in-process DeviceService gRPC
// implementation, or nil. The REST device router delegates
// POST /devices/{id}/attest to it so device attestation has exactly one
// verifier behind every transport (#226).
func (registry *HandlerRegistry) DeviceServiceServer() platformv1.DeviceServiceServer {
	return registry.params.DeviceServiceServer
}

// ComputeServiceServer returns the in-process ComputeService gRPC
// implementation used by the REST compute router, or nil.
func (registry *HandlerRegistry) ComputeServiceServer() platformv1.ComputeServiceServer {
	return registry.params.ComputeServiceServer
}

// DNSServiceServer returns the in-process DNSService gRPC implementation the
// REST DNS router delegates to, or nil.
func (registry *HandlerRegistry) DNSServiceServer() platformv1.DNSServiceServer {
	return registry.params.DNSServiceServer
}

// RegistryService returns the OCI artifact registry adapter wired
// into the daemon, or nil. Used by the /compute/images REST surface
// + the gRPC + MCP transports.
func (registry *HandlerRegistry) RegistryService() grpcapi.RegistryService {
	return registry.params.RegistryService
}

// OCIDistBackend returns the spec-compliant /v2/ distribution
// backend wired into the daemon, or nil. Used by the root-level
// /v2/ router so `crane`/`skopeo`/`oras` can push and pull.
func (registry *HandlerRegistry) OCIDistBackend() restregistry.OCIDistBackend {
	return registry.params.OCIDistBackend
}

// HealthRegistry returns the platform health registry, or nil when none is
// wired. Used by the root-level probe routes (/health, /health/live,
// /health/ready).
func (registry *HandlerRegistry) HealthRegistry() health.Registry {
	return registry.params.HealthRegistry
}

// AttestationEventReader returns the platform attestation events
// reader, or nil. Used by /api/v1/attestation/events.
func (registry *HandlerRegistry) AttestationEventReader() restattestation.EventReader {
	return registry.params.AttestationEventReader
}

// AttestationReporting returns the reporting service surface, or nil.
func (registry *HandlerRegistry) AttestationReporting() *restattestation.Reporting {
	return registry.params.AttestationReporting
}

// AttestationVerdicts returns the device verdict feed's poller, or nil.
func (registry *HandlerRegistry) AttestationVerdicts() restattestation.VerdictPoller {
	return registry.params.AttestationVerdicts
}

// GatewayControlPlane returns the gateway state store + the desired-
// config source backing /api/v1/gateway/*. Either may be nil; the
// router still mounts the surface so the structured 503 envelope
// surfaces when components are unwired.
func (registry *HandlerRegistry) GatewayControlPlane() (restgateway.GatewayStateStore, restgateway.DesiredConfigSource) {
	return registry.params.GatewayStateStore, registry.params.GatewayDesiredConfig
}

// GatewayVPNLeases returns the record of the gateways' VPN leases, or nil.
func (registry *HandlerRegistry) GatewayVPNLeases() restgateway.VPNLeaseSink {
	return registry.params.GatewayVPNLeases
}

// EABServiceServer returns the in-process EABService gRPC implementation, or nil.
func (registry *HandlerRegistry) EABServiceServer() platformv1.EABServiceServer {
	return registry.params.EABServiceServer
}

// GatewayServiceServer returns the in-process GatewayService gRPC implementation, or nil.
func (registry *HandlerRegistry) GatewayServiceServer() platformv1.GatewayServiceServer {
	return registry.params.GatewayServiceServer
}

// IDevIDServiceServer returns the in-process IDevIDService gRPC implementation, or nil.
func (registry *HandlerRegistry) IDevIDServiceServer() platformv1.IDevIDServiceServer {
	return registry.params.IDevIDServiceServer
}

// CAServiceServer returns the in-process CAService gRPC implementation, or nil.
func (registry *HandlerRegistry) CAServiceServer() platformv1.CAServiceServer {
	return registry.params.CAServiceServer
}

// InvitationServiceServer returns the in-process InvitationService gRPC implementation, or nil.
func (registry *HandlerRegistry) InvitationServiceServer() platformv1.InvitationServiceServer {
	return registry.params.InvitationServiceServer
}

// OverlayServiceServer returns the in-process OverlayService gRPC implementation, or nil.
func (registry *HandlerRegistry) OverlayServiceServer() platformv1.OverlayServiceServer {
	return registry.params.OverlayServiceServer
}

// PXEServiceServer returns the in-process PXEService gRPC implementation, or nil.
func (registry *HandlerRegistry) PXEServiceServer() platformv1.PXEServiceServer {
	return registry.params.PXEServiceServer
}

// PXEWebhookEnabled reports whether the operator enabled the PXE
// install-completion webhook (pxe.ServiceConfig.WebhookEnabled).
func (registry *HandlerRegistry) PXEWebhookEnabled() bool {
	return registry.params.PXEWebhookEnabled
}

// NTPServiceServer returns the in-process NTPService gRPC implementation, or nil.
func (registry *HandlerRegistry) NTPServiceServer() platformv1.NTPServiceServer {
	return registry.params.NTPServiceServer
}

// VPNServiceServer returns the in-process VPNService gRPC implementation, or nil.
func (registry *HandlerRegistry) VPNServiceServer() platformv1.VPNServiceServer {
	return registry.params.VPNServiceServer
}

// AppServiceServers returns the daemon's Cache, Scheduler, Messaging and
// ObjectStorage servers; a service the daemon does not wire is a nil interface.
func (registry *HandlerRegistry) AppServiceServers() restapi.AppServiceServers {
	return registry.params.AppServiceServers
}

// TenantServiceServer returns the in-process TenantService gRPC implementation, or nil.
func (registry *HandlerRegistry) TenantServiceServer() platformv1.TenantServiceServer {
	return registry.params.TenantServiceServer
}

// TPMServiceServer returns the in-process TPMService gRPC implementation, or nil.
func (registry *HandlerRegistry) TPMServiceServer() platformv1.TPMServiceServer {
	return registry.params.TPMServiceServer
}
