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

package vtpm

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TPMProvider creates and manages go-xkms TrustedPlatformModule instances
// for vTPM sockets. This provides a factory pattern for creating TPM instances
// connected to swtpm Unix domain sockets.
type TPMProvider struct {
	logger    *logging.Logger
	instances sync.Map // socketPath -> *tpmInstance
}

// tpmInstance tracks a go-xkms TPM instance.
type tpmInstance struct {
	tpm xkmssdk.TrustedPlatformModule
}

// NewTPMProvider creates a new TPM provider.
func NewTPMProvider(logger *logging.Logger) *TPMProvider {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &TPMProvider{
		logger: logger,
	}
}

// GetTPM returns a go-xkms TrustedPlatformModule connected to the specified
// swtpm socket. The TPM instance is cached for reuse.
func (p *TPMProvider) GetTPM(socketPath string) (xkmssdk.TrustedPlatformModule, error) {
	// Check cache first
	if val, ok := p.instances.Load(socketPath); ok {
		instance := val.(*tpmInstance)
		return instance.tpm, nil
	}

	// Create new transport and TPM instance
	t, err := xkmssdk.OpenUnixSocketTransport(socketPath)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	// Create TPM config for the socket
	tpmConfig := &xkmssdk.TPMConfig{
		Device: socketPath,
		Hash:   "SHA-256",
		EK: &xkmssdk.EKConfig{
			Handle:       0x81010001, // Standard EK handle
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	// Create TPM instance with custom transport
	params := &xkmssdk.TPMParams{
		Config:    tpmConfig,
		Logger:    nil, // Will use go-xkms's default logger
		Transport: t,
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil {
		// Close the transport if it implements io.Closer
		if closer, ok := t.(io.Closer); ok {
			closer.Close()
		}
		// If ErrNotInitialized, the TPM is usable but not provisioned
		if err == xkmssdk.ErrTPMNotInitialized {
			// Store even uninitialized TPM - it can still be used for basic operations
			instance := &tpmInstance{tpm: tpm}
			p.instances.Store(socketPath, instance)
			return tpm, nil
		}
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	instance := &tpmInstance{tpm: tpm}
	p.instances.Store(socketPath, instance)

	return tpm, nil
}

// simulatorCacheKey is the instance-cache key for the in-process simulator.
const simulatorCacheKey = "simulator://"

// ErrNilResolvedTarget indicates GetTPMForTarget was called without a
// resolved TPM target.
type ErrNilResolvedTarget struct{}

func (e ErrNilResolvedTarget) Error() string {
	return "vtpm: resolved TPM target is nil"
}

// ErrUnknownTPMTarget indicates a resolved target carries an unrecognized
// target kind.
type ErrUnknownTPMTarget struct {
	Target TPMTarget
}

func (e ErrUnknownTPMTarget) Error() string {
	return fmt.Sprintf("vtpm: unknown TPM target %d", int(e.Target))
}

// ErrTPMDeviceOpenFailed indicates a hardware TPM character device could not
// be opened.
type ErrTPMDeviceOpenFailed struct {
	Device string
	Cause  error
}

func (e ErrTPMDeviceOpenFailed) Error() string {
	return fmt.Sprintf("vtpm: failed to open TPM device %s: %v", e.Device, e.Cause)
}

func (e ErrTPMDeviceOpenFailed) Unwrap() error { return e.Cause }

// GetTPMForTarget returns a go-xkms TrustedPlatformModule for a resolved TPM
// target. It is the single dispatch point that makes attestation identical on
// bare metal (hardware character device), virtual hosts (swtpm socket), and
// unit-test environments (in-process simulator).
func (p *TPMProvider) GetTPMForTarget(target *ResolvedTPMTarget) (xkmssdk.TrustedPlatformModule, error) {
	if target == nil {
		return nil, ErrNilResolvedTarget{}
	}
	switch target.Target {
	case TPMTargetHardware:
		return p.GetHardwareTPM(target.Device)
	case TPMTargetSwtpm:
		return p.GetTPM(target.Device)
	case TPMTargetSimulator:
		return p.GetSimulatorTPM()
	default:
		return nil, ErrUnknownTPMTarget{Target: target.Target}
	}
}

// GetHardwareTPM returns a go-xkms TrustedPlatformModule connected to a
// hardware TPM character device (/dev/tpmrm0 or /dev/tpm0). The device must
// exist — a missing device fails closed with ErrHardwareTPMUnavailable, never
// by falling back to a software TPM. The instance is cached for reuse.
func (p *TPMProvider) GetHardwareTPM(devicePath string) (xkmssdk.TrustedPlatformModule, error) {
	if val, ok := p.instances.Load(devicePath); ok {
		return val.(*tpmInstance).tpm, nil
	}

	info, err := os.Stat(devicePath)
	if err != nil {
		return nil, ErrHardwareTPMUnavailable{Device: devicePath, Cause: err}
	}
	if info.Mode()&os.ModeDevice == 0 {
		return nil, ErrHardwareTPMUnavailable{Device: devicePath, Cause: ErrNotCharDevice{Path: devicePath}}
	}

	// go-xkms opens non-socket device paths directly; no custom transport is
	// required for a character device.
	params := &xkmssdk.TPMParams{
		Config: p.deviceTPMConfig(devicePath, false),
	}
	return p.openAndCache(devicePath, params, func(cause error) error {
		return ErrTPMDeviceOpenFailed{Device: devicePath, Cause: cause}
	})
}

// GetSimulatorTPM returns a go-xkms TrustedPlatformModule backed by the
// in-process TPM simulator. Simulator support is compiled into go-xkms behind
// its tpm_simulator build tag; when absent the open fails with the upstream
// typed error rather than silently substituting another TPM.
func (p *TPMProvider) GetSimulatorTPM() (xkmssdk.TrustedPlatformModule, error) {
	if val, ok := p.instances.Load(simulatorCacheKey); ok {
		return val.(*tpmInstance).tpm, nil
	}
	params := &xkmssdk.TPMParams{
		Config: p.deviceTPMConfig("", true),
	}
	return p.openAndCache(simulatorCacheKey, params, func(cause error) error {
		return ErrTPMDeviceOpenFailed{Device: simulatorCacheKey, Cause: cause}
	})
}

// deviceTPMConfig builds the TPM configuration shared by the hardware and
// simulator open paths (SHA-256 hash, standard RSA EK handle).
func (p *TPMProvider) deviceTPMConfig(device string, useSimulator bool) *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		Device:       device,
		UseSimulator: useSimulator,
		Hash:         "SHA-256",
		EK: &xkmssdk.EKConfig{
			Handle:       0x81010001, // Standard EK handle
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		},
	}
}

// openAndCache opens a TPM with the provided parameters and caches it under
// key. An uninitialized (unprovisioned) TPM is still cached and returned so
// callers can perform basic operations; any other failure is wrapped by
// wrapErr.
func (p *TPMProvider) openAndCache(key string, params *xkmssdk.TPMParams, wrapErr func(error) error) (xkmssdk.TrustedPlatformModule, error) {
	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return nil, wrapErr(err)
	}
	instance := &tpmInstance{tpm: tpm}
	p.instances.Store(key, instance)
	return tpm, nil
}

// CloseTPM closes the TPM instance for the specified socket and removes it from cache.
func (p *TPMProvider) CloseTPM(socketPath string) error {
	if val, ok := p.instances.LoadAndDelete(socketPath); ok {
		instance := val.(*tpmInstance)
		return instance.tpm.Close()
	}
	return nil
}

// CloseAll closes all cached TPM instances.
func (p *TPMProvider) CloseAll() error {
	var lastErr error
	p.instances.Range(func(key, value any) bool {
		socketPath := key.(string)
		instance := value.(*tpmInstance)
		if err := instance.tpm.Close(); err != nil {
			p.logger.Warn("Failed to close TPM instance", "socket", socketPath, "error", err)
			lastErr = err
		}
		p.instances.Delete(key)
		return true
	})
	return lastErr
}

// TPMOperations provides high-level TPM operations using go-xkms.
// This wraps a go-xkms TrustedPlatformModule and provides operations
// specific to vTPM bundle management.
type TPMOperations struct {
	tpm         xkmssdk.TrustedPlatformModule
	socketPath  string
	algorithm   EKAlgorithm
	logger      *logging.Logger
	provisioned bool
}

// NewTPMOperations creates a new TPM operations wrapper configured for the
// specified EK algorithm. The algorithm determines the TCG NV index used
// for EK certificate storage (RSA: 0x01C00002, ECC: 0x01C0000A). deviceCN
// is the common name of the IAK that Provision creates; it is the bundle
// hostname. sealedDir is the bundle's sealed-data directory (sealedDataDir).
func NewTPMOperations(socketPath, sealedDir string, algorithm EKAlgorithm, deviceCN string, logger *logging.Logger) (*TPMOperations, error) {
	// Open transport to swtpm socket
	t, err := xkmssdk.OpenUnixSocketTransport(socketPath)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	ops, err := newTPMOperations(t, socketPath, sealedDir, algorithm, deviceCN, logger)
	if err != nil {
		// Close the transport if it implements io.Closer
		if closer, ok := t.(io.Closer); ok {
			closer.Close()
		}
		return nil, err
	}
	return ops, nil
}

// newTPMOperations builds the go-xkms TPM over an open transport. The TPM keeps
// the blobs of the objects it seals in a file store rooted at sealedDir, so a
// later TPMOperations on the same bundle unseals them. A TPM with no persistent
// EK opens unprovisioned (ErrTPMNotInitialized); ProvisionIfNew provisions it.
func newTPMOperations(t transport.TPM, socketPath, sealedDir string, algorithm EKAlgorithm, deviceCN string, logger *logging.Logger) (*TPMOperations, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	sealedStore, err := xkmssdk.NewFileStorageBackend(sealedDir)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: &WrappedError{Msg: "failed to open the sealed-data store", Err: err}}
	}

	params := &xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(slog.Default(), sealedStore),
		Config:    tpmOperationsConfig(socketPath, algorithm, deviceCN),
		Logger:    nil, // Will use go-xkms's default logger
		Transport: t,
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil && !errors.Is(err, xkmssdk.ErrTPMNotInitialized) {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	return &TPMOperations{
		tpm:         tpm,
		socketPath:  socketPath,
		algorithm:   algorithm,
		logger:      logger,
		provisioned: err == nil,
	}, nil
}

// sealedDataDir is the directory, inside a bundle's TPM state directory, that
// holds the blobs of the objects the bundle's vTPM seals.
func sealedDataDir(tpmDir string) string {
	return filepath.Join(tpmDir, "sealed")
}

// tpmOperationsConfig builds the configuration of a bundle vTPM: an EK of
// the requested algorithm, the TCG shared SRK and an IAK named deviceCN.
// go-xkms refuses to create an IAK without a common name (or a device model
// and serial number), so Provision fails on a configuration without one.
func tpmOperationsConfig(socketPath string, algorithm EKAlgorithm, deviceCN string) *xkmssdk.TPMConfig {
	// Configure EK based on algorithm with TCG-specified NV indices
	var ekConfig *xkmssdk.EKConfig
	switch algorithm {
	case EKAlgorithmECC:
		ekConfig = &xkmssdk.EKConfig{
			Handle:       0x81010002, // ECC EK handle
			CertHandle:   NVIndexECCEKCert,
			KeyAlgorithm: "ECDSA",
			ECCConfig: &xkmssdk.ECCConfig{
				Curve: "P-256",
			},
		}
	case EKAlgorithmRSA:
		fallthrough
	default:
		ekConfig = &xkmssdk.EKConfig{
			Handle:       0x81010001, // RSA EK handle
			CertHandle:   NVIndexRSAEKCert,
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		}
	}

	// The configuration must be complete enough for a full Provision cycle
	// (EK + shared SRK + IAK): go-xkms dereferences the SSRK and IAK sections
	// during ProvisionOwner/CreateIAK. PlatformPolicy stays false — bundle
	// vTPM state later runs inside a guest whose PCR values differ from this
	// host, so host-PCR-bound policies would render the guest state unusable.
	return &xkmssdk.TPMConfig{
		Device:          socketPath,
		Hash:            "SHA-256",
		PlatformPCR:     16,
		PlatformPCRBank: "SHA256",
		EK:              ekConfig,
		SSRK: &xkmssdk.SRKConfig{
			Handle:       0x81000001, // TCG shared SRK handle
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &xkmssdk.IAKConfig{
			CN:                 deviceCN,
			Handle:             0x81020001, // Default IAK handle
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		},
	}
}

// Close closes the TPM connection.
func (ops *TPMOperations) Close() error {
	if ops.tpm != nil {
		return ops.tpm.Close()
	}
	return nil
}

// TPM returns the underlying go-xkms TrustedPlatformModule.
func (ops *TPMOperations) TPM() xkmssdk.TrustedPlatformModule {
	return ops.tpm
}

// Provision provisions the vTPM with EK, SRK, and IAK using go-xkms.
// This should be called once when creating a new vTPM bundle.
func (ops *TPMOperations) Provision(soPIN string) error {
	ops.logger.Debug("Provisioning vTPM", "algorithm", string(ops.algorithm))

	password, err := xkmssdk.NewPassword([]byte(soPIN))
	if err != nil {
		return ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to hold the SO PIN", Err: err}}
	}
	if err := ops.tpm.Provision(password); err != nil {
		return ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to provision TPM", Err: err}}
	}
	ops.provisioned = true

	ops.logger.Debug("vTPM provisioned successfully")
	return nil
}

// ProvisionIfNew provisions a vTPM that opened without a persistent EK: a
// bundle created without EK-certificate injection reaches its first Start
// unprovisioned, and Quote, Seal and ExtendPCR need its keys. A provisioned
// vTPM keeps the keys it already has; its IAK is loaded, and a provisioned
// vTPM without one is refused with ErrVTPMAttestationKeyMissing.
func (ops *TPMOperations) ProvisionIfNew() error {
	if !ops.provisioned {
		return ops.Provision("")
	}
	// A provisioned vTPM opens without its IAK loaded, and Quote signs with
	// the IAK: load it from its persistent handle now, once, so every Quote
	// on this instance finds it.
	if _, err := ops.tpm.IAKAttributes(); err != nil {
		return ErrVTPMAttestationKeyMissing{SocketPath: ops.socketPath, Cause: err}
	}
	return nil
}

// GetEKPublicKey returns the EK public key using go-xkms.
// The TPM must be provisioned first.
func (ops *TPMOperations) GetEKPublicKey() (crypto.PublicKey, error) {
	// EK() answers only from the cached EK attributes, which Provision does
	// not fill; EKAttributes reads the persistent EK and caches them.
	if _, err := ops.tpm.EKAttributes(); err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: err}
	}
	pubKey, err := ops.tpm.EK()
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: err}
	}
	if pubKey == nil {
		return nil, ErrEKCertInjectionFailed{Cause: &MessageError{Msg: "EK not available - TPM may not be provisioned"}}
	}
	return pubKey, nil
}

// InjectEKCertificate injects an EK certificate into the TPM's NV RAM
// using go-xkms's ProvisionEKCert method.
func (ops *TPMOperations) InjectEKCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrEKCertInjectionFailed{Cause: &MessageError{Msg: "certificate cannot be nil"}}
	}

	ops.logger.Debug("Injecting EK certificate",
		"algorithm", string(ops.algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", ops.algorithm.NVIndex()))

	// The write goes over the transport the provisioning flow already holds
	// (swtpm serves one client at a time) and is split at the TPM's
	// TPM_PT_NV_BUFFER_MAX. go-xkms ProvisionEKCert issues the whole
	// certificate as one TPM2_NV_Write, which swtpm rejects with TPM_RC_SIZE
	// once the certificate exceeds its 1024-byte buffer.
	injector := NewEKCertInjector(ops.socketPath, ops.logger)
	if err := injector.writeCertificate(ops.tpm.Transport(), cert, ops.algorithm); err != nil {
		return ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to inject EK certificate", Err: err}}
	}

	ops.logger.Debug("EK certificate injected successfully")
	return nil
}

// ReadPCRs reads the specified PCR values using go-xkms's ReadPCRs method.
func (ops *TPMOperations) ReadPCRs(pcrs []int) (map[int][]byte, error) {
	// Convert int slice to uint slice for go-xkms
	pcrList := make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		pcrList[i] = uint(pcr)
	}

	banks, err := ops.tpm.ReadPCRs(pcrList)
	if err != nil {
		return nil, err
	}

	// Extract SHA256 bank values
	result := make(map[int][]byte)
	for _, bank := range banks {
		if bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				result[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	return result, nil
}

// Quote generates a TPM quote using go-xkms's Quote method.
// Note: This requires an initialized IAK. For basic vTPM operations
// without IAK, use QuoteWithKey.
func (ops *TPMOperations) Quote(nonce []byte, pcrs []int) (*QuoteResult, error) {
	// Convert int slice to uint slice
	pcrList := make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		pcrList[i] = uint(pcr)
	}

	quote, err := ops.tpm.Quote(pcrList, nonce)
	if err != nil {
		return nil, err
	}

	// Convert PCR bytes back to map
	pcrBanks, err := xkmssdk.DecodePCRs(quote.PCRs)
	if err != nil {
		return nil, err
	}

	pcrValues := make(map[int][]byte)
	for _, bank := range pcrBanks {
		if bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				pcrValues[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	return &QuoteResult{
		Quote:         quote.Quoted,
		Signature:     quote.Signature,
		PCRValues:     pcrValues,
		HashAlgorithm: "SHA256",
	}, nil
}

// Seal encrypts data to the TPM using go-xkms's Seal method.
func (ops *TPMOperations) Seal(ctx context.Context, data []byte, pcrs []int, authValue string) (*xkmssdk.SealedData, error) {
	// Build key attributes for sealing
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:        "vtpm-sealed-data",
		StoreType: xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Get SSRK as parent
	ssrkAttrs, err := ops.tpm.SSRKAttributes()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get SSRK attributes", Err: err}
	}
	keyAttrs.Parent = ssrkAttrs

	// Set auth value if provided
	if authValue != "" {
		password, err := xkmssdk.NewPassword([]byte(authValue))
		if err != nil {
			return nil, &WrappedError{Msg: "failed to hold the key authorization value", Err: err}
		}
		keyAttrs.Password = password
	}

	// Build TPM policy for PCR binding
	var tpmPolicy *xkmssdk.TPMSealPolicy
	var pcrSelect []byte
	if len(pcrs) > 0 {
		pcrSelect = pcrBitmask(pcrs)
		pcrSelection := sealPCRSelection(pcrSelect)

		// The SDK copies PCRSelection onto the key attributes but never makes
		// it the sealed object's authPolicy, and its template keeps
		// UserWithAuth set, so a plain password session would unseal the data
		// whatever the PCRs hold. Bind the template here instead: PolicyPCR
		// (then PolicyAuthValue when a password is set) as the authPolicy,
		// with UserWithAuth cleared so only that policy authorizes Unseal.
		digest, err := ops.pcrPolicyDigest(pcrSelection, keyAttrs.Password != nil)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to compute the PCR seal policy", Err: err}
		}
		keyAttrs.TPMAttributes.Template = tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: tpm2.TPM2BDigest{Buffer: digest},
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
			},
		}
		tpmPolicy = &xkmssdk.TPMSealPolicy{
			PCRSelection: pcrSelection,
			HashAlg:      tpm2.TPMAlgSHA256,
		}
	}

	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: keyAttrs,
		TPMPolicy:     tpmPolicy,
	}

	sealed, err := ops.tpm.Seal(ctx, data, sealOpts)
	if err != nil {
		return nil, err
	}
	if pcrSelect != nil {
		if sealed.Metadata == nil {
			sealed.Metadata = make(map[string][]byte)
		}
		sealed.Metadata[sealPCRSelectMetadataKey] = pcrSelect
	}
	return sealed, nil
}

// Unseal decrypts data from the TPM using go-xkms's Unseal method.
func (ops *TPMOperations) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, authValue string) ([]byte, error) {
	// Build key attributes for unsealing
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:        "vtpm-sealed-data",
		StoreType: xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Get SSRK as parent
	ssrkAttrs, err := ops.tpm.SSRKAttributes()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get SSRK attributes", Err: err}
	}
	keyAttrs.Parent = ssrkAttrs

	// Set auth value if provided
	var password xkmssdk.Password
	if authValue != "" {
		held, err := xkmssdk.NewPassword([]byte(authValue))
		if err != nil {
			return nil, &WrappedError{Msg: "failed to hold the key authorization value", Err: err}
		}
		password = held
	}

	// A PCR-bound object accepts only its PCR policy session, which the SDK's
	// Unseal cannot build, so it is loaded and unsealed here.
	if sealed != nil {
		if pcrSelect, ok := sealed.Metadata[sealPCRSelectMetadataKey]; ok {
			return ops.unsealPCRBound(keyAttrs, sealed, pcrSelect, password)
		}
	}

	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: keyAttrs,
		Password:      password,
	}

	return ops.tpm.Unseal(ctx, sealed, unsealOpts)
}

// ExtendPCR extends a PCR with the provided data using go-xkms.
func (ops *TPMOperations) ExtendPCR(pcrIndex int, data []byte) error {
	return ops.tpm.ExtendPCR(pcrIndex, "sha256", data)
}

// ReadPCR reads a single PCR value.
func (ops *TPMOperations) ReadPCR(pcrIndex int) ([]byte, error) {
	values, err := ops.ReadPCRs([]int{pcrIndex})
	if err != nil {
		return nil, err
	}
	return values[pcrIndex], nil
}

// pcrBitmask converts a list of PCR indices to a TPM PCR bitmask.
func pcrBitmask(pcrs []int) []byte {
	mask := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr <= 23 {
			mask[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return mask
}

// sealPCRSelectMetadataKey names the SealedData metadata entry that records
// the PCR bitmask a sealed object's authPolicy is bound to.
const sealPCRSelectMetadataKey = "vtpm:pcr-select"

// sealPCRSelection returns the SHA-256 bank selection for a PCR bitmask.
func sealPCRSelection(pcrSelect []byte) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: pcrSelect,
			},
		},
	}
}

// applyPCRPolicy runs the seal policy on a policy session: PolicyPCR over the
// selection, then PolicyAuthValue when the object carries a password. Seal
// computes the authPolicy and Unseal satisfies it with the same sequence.
func applyPCRPolicy(t transport.TPM, session tpm2.TPMHandle, sel tpm2.TPMLPCRSelection, withAuth bool) error {
	if _, err := (tpm2.PolicyPCR{PolicySession: session, Pcrs: sel}).Execute(t); err != nil {
		return err
	}
	if withAuth {
		if _, err := (tpm2.PolicyAuthValue{PolicySession: session}).Execute(t); err != nil {
			return err
		}
	}
	return nil
}

// pcrPolicyDigest computes, in a trial session, the authPolicy that binds a
// sealed object to the current values of the selected PCRs.
func (ops *TPMOperations) pcrPolicyDigest(sel tpm2.TPMLPCRSelection, withAuth bool) ([]byte, error) {
	t := ops.tpm.Transport()
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeSession() }()

	if err := applyPCRPolicy(t, session.Handle(), sel, withAuth); err != nil {
		return nil, err
	}
	rsp, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(t)
	if err != nil {
		return nil, err
	}
	return rsp.PolicyDigest.Buffer, nil
}

// unsealPCRBound loads a PCR-bound sealed object under its parent and unseals
// it through a policy session, which fails once a selected PCR has changed.
func (ops *TPMOperations) unsealPCRBound(keyAttrs *xkmssdk.KeyAttributes, sealed *xkmssdk.SealedData, pcrSelect []byte, password xkmssdk.Password) ([]byte, error) {
	t := ops.tpm.Transport()
	parent := keyAttrs.Parent.TPMAttributes
	parentName, _, err := ops.tpm.ReadHandle(parent.Handle)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read the sealing parent", Err: err}
	}

	parentSession, closeParent, err := ops.tpm.CreateSession(keyAttrs)
	if err != nil {
		if closeParent != nil {
			_ = closeParent()
		}
		return nil, &WrappedError{Msg: "failed to open the sealing parent session", Err: err}
	}
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parent.Handle,
			Name:   parentName,
			Auth:   parentSession,
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: sealed.TPMPrivate},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](sealed.TPMPublic),
	}.Execute(t)
	closeErr := closeParent()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to load the sealed object", Err: err}
	}
	defer ops.tpm.Flush(loaded.ObjectHandle)
	if closeErr != nil {
		return nil, &WrappedError{Msg: "failed to close the sealing parent session", Err: closeErr}
	}

	var authOpts []tpm2.AuthOption
	if password != nil {
		authOpts = append(authOpts, tpm2.Auth(password.Bytes()))
	}
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, authOpts...)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open the PCR policy session", Err: err}
	}
	defer func() { _ = closeSession() }()

	if err := applyPCRPolicy(t, session.Handle(), sealPCRSelection(pcrSelect), password != nil); err != nil {
		return nil, &WrappedError{Msg: "PCR policy not satisfied", Err: err}
	}
	unsealed, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   session,
		},
	}.Execute(t)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to unseal the PCR-bound object", Err: err}
	}
	return unsealed.OutData.Buffer, nil
}

// certFingerprint calculates the SHA-256 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("sha256:%x", hash)
}
