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
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/system"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"

	proto "github.com/jeremyhahn/go-quicbaas/api/proto"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// AttestationImporter defines the minimal interface required for importing
// attestation data from TCG enrollments. This interface is satisfied by
// ca.CertificateAuthority and allows for easier testing with mocks.
type AttestationImporter interface {
	ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error
	ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error
	ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error
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

			if err := caInstance.ImportAttestationEventLog(akAttrs, ctx.TCGData.EventLog); err != nil {
				logger.Error("Failed to import attestation event log",
					slog.String("cn", akAttrs.CN),
					slog.String("error", err.Error()))
				return fmt.Errorf("failed to import attestation event log for %s: %w", akAttrs.CN, err)
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
				return fmt.Errorf("failed to unpack ProdCaData for %s: %w", akAttrs.CN, err)
			}

			if prodCaData != nil {
				// Convert ProdCaData to Quote structure
				quote := prodCaData.ToQuote()

				// Import Quote (store the Quoted data - matches local attestation behavior)
				if len(quote.Quoted) > 0 {
					if err := caInstance.ImportAttestationQuote(akAttrs, quote.Quoted); err != nil {
						logger.Error("Failed to import attestation quote",
							slog.String("cn", akAttrs.CN),
							slog.String("error", err.Error()))
						return fmt.Errorf("failed to import attestation quote for %s: %w", akAttrs.CN, err)
					}

					logger.Info("Successfully imported attestation quote",
						slog.String("cn", akAttrs.CN),
						slog.Int("quoted_size", len(quote.Quoted)),
						slog.Int("signature_size", len(quote.Signature)),
						slog.Int("nonce_size", len(quote.Nonce)))
				}

				// Import PCRs
				if len(quote.PCRs) > 0 {
					if err := caInstance.ImportAttestationPCRs(akAttrs, quote.PCRs); err != nil {
						logger.Error("Failed to import attestation PCRs",
							slog.String("cn", akAttrs.CN),
							slog.String("error", err.Error()))
						return fmt.Errorf("failed to import attestation PCRs for %s: %w", akAttrs.CN, err)
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

// NewDNSRegistrationHook creates an order finalization hook that registers
// DNS records for enrolled devices. This hook is called by go-trusted-ca's
// generic hook system after successful order finalization.
//
// The CA has no knowledge of DNS - this hook is entirely defined within
// go-trusted-platform and registered with the CA's generic hook registry.
func NewDNSRegistrationHook(dnsService DNSRegistrar, internalDomain string, logger *slog.Logger) trustedca.ACMEOrderFinalizeHook {
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

		// Construct FQDN from device identity and internal domain
		// Format: {model}-{serial}.{internal-domain}
		fqdn := fmt.Sprintf("%s-%s.%s",
			ctx.TCGData.ProductModel,
			ctx.TCGData.ProductSerial,
			internalDomain)

		logger.Info("Attempting DNS registration",
			slog.String("fqdn", fqdn),
			slog.String("ip", ctx.ClientIP),
			slog.String("internal_domain", internalDomain))

		// Register the DNS record using go-trusted-platform's DNS service
		_, err := dnsService.Register(context.Background(), fqdn, ctx.ClientIP)
		if err != nil {
			logger.Error("DNS registration failed",
				slog.String("fqdn", fqdn),
				slog.String("error", err.Error()))
			return fmt.Errorf("failed to register DNS record for %s: %w", fqdn, err)
		}

		logger.Info("Registered DNS record for enrolled device",
			slog.String("fqdn", fqdn),
			slog.String("ip", ctx.ClientIP),
			slog.String("model", ctx.TCGData.ProductModel),
			slog.String("serial", ctx.TCGData.ProductSerial))

		return nil
	}
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
			return fmt.Errorf("SDN enrollment hook failed: %w", err)
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
	Signer(attrs *xkmssdk.KeyAttributes) (crypto.Signer, error)
}

type RestHandlerRegistry interface {
	ACMERestService() trustedca.ACMERestServicer
	DeviceRestHandler() device.RestHandler
	ConfigDeliveryHandler() configdelivery.RestHandler
	IAMClients() (iampb.IAMServiceClient, iampb.PEPServiceClient)
	JSONWebTokenHandler() jwt.TokenHandler
	KMSClients() (proto.KeyManagementClient, proto.CryptoClient, proto.DEKManagementClient, proto.SecretsManagementClient)
	MTLSMiddleware() middleware.MTLSMiddleware
	PlatformRestRouter() *platform.PlatformRouter
	ResponseWriter() response.HttpWriter
	SDNService() platformv1.SDNServiceServer
	TPM() xkmssdk.TrustedPlatformModule
	VTPMService() vtpm.VTPMService
	WebAuthnRestService() webauthn.RestHandler
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

type RegistryParams struct {
	ACMEServerConfig        *ACMEServerConfig
	ACMEStorageFactory      trustedca.ACMEStorageFactory
	CA                      trustedca.CACertificateAuthority
	CAConfig                *trustedca.CAConfig
	CryptoClient            proto.CryptoClient
	Debug                   bool
	DEKManagementClient     proto.DEKManagementClient
	DNSConfig               *dns.Config
	HTTPWriter              response.HttpWriter
	IAMServiceClient        iampb.IAMServiceClient
	XKMS                    XKMSSigner
	KeyManagementClient     proto.KeyManagementClient
	JWTAudience             string
	JWTClaimsIssuer         string
	JWTExpiration           int
	Logger                  *logging.Logger
	PEPServiceClient        iampb.PEPServiceClient
	SDNEnrollmentHook       *policy.SDNEnrollmentHook
	SDNService              platformv1.SDNServiceServer
	SecretsManagementClient proto.SecretsManagementClient
	ServerKeyAttributes     *xkmssdk.KeyAttributes
	ServiceRegistry         *service.Registry
	TPM                     xkmssdk.TrustedPlatformModule
	VTPMService             vtpm.VTPMService
	WebServiceConfig        *Config
	WebAuthnConfig          *webauthn.Config
}

type HandlerRegistry struct {
	jwtService *jwt.Service
	params     RegistryParams
	RestHandlerRegistry
}

func NewHandlerRegistry(params RegistryParams) RestHandlerRegistry {
	jwtParams := jwt.ServiceParams{
		Audience:   params.JWTAudience,
		Expiration: params.JWTExpiration,
		Issuer:     params.JWTClaimsIssuer,
		KeyAttrs:   params.ServerKeyAttributes,
		XKMS:       params.XKMS,
	}
	jwtService, err := jwt.NewService(jwtParams)
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
	return handler
}

func (registry *HandlerRegistry) KMSClients() (proto.KeyManagementClient, proto.CryptoClient, proto.DEKManagementClient, proto.SecretsManagementClient) {
	return registry.params.KeyManagementClient, registry.params.CryptoClient, registry.params.DEKManagementClient, registry.params.SecretsManagementClient
}

func (registry *HandlerRegistry) IAMClients() (iampb.IAMServiceClient, iampb.PEPServiceClient) {
	return registry.params.IAMServiceClient, registry.params.PEPServiceClient
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

// WebAuthnRestService returns the WebAuthn REST handler, or nil if WebAuthn
// is not configured. Callers must check for nil before using the handler.
func (registry *HandlerRegistry) WebAuthnRestService() webauthn.RestHandler {
	if !webauthn.IsConfigured(registry.params.WebAuthnConfig) {
		registry.params.Logger.Warn("WebAuthn not configured, WebAuthn routes will not be registered")
		return nil
	}
	params := webauthn.ServiceParams{
		Config:              registry.params.WebAuthnConfig,
		Debug:               registry.params.Debug,
		JWTService:          registry.jwtService,
		Logger:              registry.params.Logger,
		RegistrationService: registry.params.ServiceRegistry.RegistrationService(),
		ResponseWriter:      registry.params.HTTPWriter,
		SessionService:      registry.params.ServiceRegistry.WebAuthnSessionService(),
		UserService:         registry.params.ServiceRegistry.UserService(),
		TenantUserService:   registry.params.ServiceRegistry.TenantUserService(),
		InvitationService:   registry.params.ServiceRegistry.InvitationService(),
	}
	handler, err := webauthn.NewHandler(params)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}

func (registry *HandlerRegistry) DeviceRestHandler() device.RestHandler {
	// Check if SDN enrollment hook is available
	if registry.params.SDNEnrollmentHook == nil {
		registry.params.Logger.Debug("SDN enrollment hook is nil - device routes not registered")
		return nil
	}

	// Create the ARP table
	arpTable := arp.NewTable()

	// Create an enrollment hook profile service that queries pending activations
	profileService := NewEnrollmentHookProfileService(registry.params.SDNEnrollmentHook)

	return device.NewHandler(
		registry.params.Logger,
		registry.params.HTTPWriter,
		registry.params.SDNEnrollmentHook.PolicyEngine(),
		profileService,
		arpTable,
	)
}

// ConfigDeliveryHandler returns a REST handler for pre-enrollment config
// delivery. This creates an in-memory service with a nonce store for devices
// to fetch their platform configuration at boot time.
// ProfileService and EABService are wired in when available — nonce and session
// endpoints work even without them for the interactive QR provisioning flow.
func (registry *HandlerRegistry) ConfigDeliveryHandler() configdelivery.RestHandler {
	svc, err := configdelivery.NewService(configdelivery.ServiceParams{
		Logger: registry.params.Logger,
	})
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

func (registry *HandlerRegistry) MTLSMiddleware() middleware.MTLSMiddleware {
	// Get the trusted root certificate from the CA
	rootCert, err := registry.params.CA.TrustedRoot()
	if err != nil {
		registry.params.Logger.FatalError(fmt.Errorf("failed to get trusted root certificate: %w", err))
	}

	// Create a cert pool with the trusted root
	trustedRoots, err := registry.params.CA.TrustedRootCertPool(rootCert, nil)
	if err != nil {
		registry.params.Logger.FatalError(fmt.Errorf("failed to create trusted root cert pool: %w", err))
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

	// Register DNS hook if DNS service is available
	// This hook is defined entirely within go-trusted-platform - the CA has no knowledge of DNS
	dnsService := registry.params.ServiceRegistry.DNSService()
	if dnsService == nil {
		registry.params.Logger.Warn("DNS service is nil - DNS registration hook not registered")
	} else if registry.params.ACMEServerConfig.InternalDomain == "" {
		registry.params.Logger.Warn("InternalDomain is empty - DNS registration hook not registered")
	} else {
		dnsHook := NewDNSRegistrationHook(
			dnsService,
			registry.params.ACMEServerConfig.InternalDomain,
			registry.params.Logger.Slog())
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

	params := &trustedca.ACMERestServiceParams{
		BaseRESTURI:             registry.params.ACMEServerConfig.BaseRESTURI,
		CA:                      registry.params.CA,
		CAAIdentities:           registry.params.ACMEServerConfig.CAAIdentities,
		ChallengeMap:            registry.params.ACMEServerConfig.ChallengeMap,
		ExternalAccountRequired: registry.params.ACMEServerConfig.ExternalAccountRequired,
		Logger:                  registry.params.Logger.Slog(),
		OrderFinalizeHooks:      hookRegistry,
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
	return platform.NewPlatformRouter(
		registry.params.Logger,
		registry.params.HTTPWriter,
	)
}
