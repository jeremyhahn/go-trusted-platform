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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// BMCRestoreResult is the full outcome of a BMC factory-certificate restore ceremony.
type BMCRestoreResult struct {
	// DeviceID is the platform device entity ID.
	DeviceID uint64

	// Endpoint is the host:port used for the BMC HTTPS connection.
	Endpoint string

	// Hostname is the bare hostname of the BMC address (no port).
	Hostname string

	// NewCertMeta holds auditable metadata from the new self-signed
	// certificate that the BMC generated during the restore.
	NewCertMeta BMCFactoryCertMeta

	// NewCertPEM is the PEM-encoded new self-signed certificate for
	// client-side inspection. Never written to disk server-side.
	NewCertPEM []byte

	// Steps records the ordered ceremony steps and their outcomes.
	Steps []BMCEnrollStep
}

// restoreCore bundles all dependencies for the restore ceremony into a
// testable unit. App.RestoreBMC binds these from app state; tests inject fakes.
type restoreCore struct {
	// restorer performs the vendor-specific cert restore operation.
	// When nil the restore-cert step is skipped with an error.
	restorer interface {
		RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error)
		Close() error
	}

	// pinDeleter removes the stored TOFU SPKI pin for the BMC endpoint.
	// May be nil when no pin store is available; deletion is then skipped
	// (non-fatal: the resolver will detect the self-signed cert on next
	// connection and update the pin via TOFU).
	pinDeleter func(ctx context.Context, host string, port int) error

	// daneUnpublish removes TLSA records for the BMC endpoint.
	// May be nil when DANE is not configured; set to nil when
	// bootstrap.DANEPublisher.RemoveForHostname is unavailable.
	daneUnpublish func(ctx context.Context, hostname string, port uint16, zoneName string) error

	// deviceLoader loads a Device entity by ID.
	deviceLoader func(ctx context.Context, id uint64) (*entities.Device, error)

	// deviceSaver persists a Device entity.
	deviceSaver func(ctx context.Context, d *entities.Device) error
}

// RestoreBMC performs the BMC factory-certificate restore ceremony for the
// device identified by deviceID. The ceremony:
//
//  1. Instructs the BMC to regenerate its default self-signed certificate.
//  2. Deletes the stored SPKI pin from the platform credential/trust store.
//  3. Unpublishes DANE TLSA records (if previously published).
//  4. Updates Device.BMCEnrollment to reflect the unenrolled/restored state.
//
// Each step is recorded independently so partial progress is visible to the
// caller even when a later step fails.
//
// "Restore --factory" does NOT re-upload the backed-up factory certificate
// (we never held its private key). It instructs the BMC firmware to
// regenerate a new default/self-signed cert, then cleans up platform-side
// trust state: SPKI pin deleted, DANE TLSA records removed, Device entity
// updated to clear enrollment fields.
func (app *App) RestoreBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config) (*BMCRestoreResult, error) {
	if bmcCfg == nil {
		return nil, bmc.ErrNilConfig{}
	}

	resolver := app.TrustResolver()
	if resolver == nil {
		return nil, ErrBMCEnrollNoTrustResolver{}
	}

	bmcCfg.TLS = &resolverTLSProvider{resolver: resolver, class: trust.ClassBMC}

	host := bmcCfg.Address
	endpoint := bmc.HTTPSEndpoint(bmcCfg)

	// Determine internal zone name for DANE unpublish.
	internalZone := ""
	if app.DNSConfig != nil && app.DNSConfig.InternalServer != nil {
		internalZone = app.DNSConfig.InternalServer.Zone.Name
	}

	// Wire credential store for pin deletion.
	var pinDeleter func(ctx context.Context, host string, port int) error
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if ok && dbFactory != nil {
		if sdkClient := dbFactory.SDKClient(); sdkClient != nil {
			if pinStore, err := quicbaas.NewTOFUPinStore(sdkClient); err == nil {
				pinDeleter = func(ctx context.Context, h string, p int) error {
					return pinStore.Delete(ctx, h, p)
				}
			}
		}
	}

	// Wire DANE unpublish when DANE is configured.
	var daneUnpublish func(ctx context.Context, hostname string, port uint16, zoneName string) error
	if app.DNSConfig != nil &&
		app.DNSConfig.DANE != nil &&
		app.DNSConfig.DANE.Enabled &&
		app.DNSService != nil {
		dp := app.ensureDANEPublisher()
		daneUnpublish = func(ctx context.Context, hostname string, port uint16, zoneName string) error {
			hn := strings.TrimSuffix(hostname, ".")
			return dp.RemoveForHostname(ctx, hn, port, zoneName)
		}
	}

	// Wire the factory-cert restorer via AutoCertManager when cert config present.
	core := &restoreCore{
		pinDeleter:    pinDeleter,
		daneUnpublish: daneUnpublish,
		deviceLoader:  app.loadDeviceForEnroll,
		deviceSaver:   app.saveDeviceForEnroll,
	}
	if bmcCfg.Certificate != nil {
		mgr, err := bmc.NewAutoCertManager(bmcCfg, bmc.CertBackendAuto, app.Logger.Slog())
		if err == nil {
			core.restorer = mgr
		}
	}

	return runRestoreCore(ctx, deviceID, host, endpoint, internalZone, core)
}

// runRestoreCore executes the ordered restore ceremony steps using the
// narrow interfaces in core. It is the testable inner function; App.RestoreBMC
// binds concrete implementations.
func runRestoreCore(
	ctx context.Context,
	deviceID uint64,
	host, endpoint, internalZone string,
	core *restoreCore,
) (*BMCRestoreResult, error) {

	result := &BMCRestoreResult{
		DeviceID: deviceID,
		Endpoint: endpoint,
		Hostname: host,
	}

	// ----------------------------------------------------------------
	// Step 1: restore-cert — instruct BMC to regenerate default SSL cert.
	// ----------------------------------------------------------------
	if core.restorer == nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "restore-cert",
			OK:     false,
			Detail: "no cert restorer available (BMC certificate config required)",
		})
		return result, ErrBMCRestoreNoCertRestorer{DeviceID: deviceID}
	}

	newCert, restoreErr := core.restorer.RestoreFactoryCertificate(ctx)
	_ = core.restorer.Close()
	if restoreErr != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "restore-cert",
			OK:     false,
			Detail: restoreErr.Error(),
		})
		return result, ErrBMCRestoreCert{DeviceID: deviceID, Cause: restoreErr}
	}

	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	result.NewCertPEM = newCertPEM
	result.NewCertMeta = BMCFactoryCertMeta{
		Subject:      newCert.Subject.String(),
		Issuer:       newCert.Issuer.String(),
		SerialNumber: newCert.SerialNumber.String(),
		NotBefore:    newCert.NotBefore,
		NotAfter:     newCert.NotAfter,
		SPKISHA256:   certSPKISHA256(newCert),
		SHA256:       certDERSHA256(newCert),
		CapturedAt:   time.Now().UTC(),
	}
	result.Steps = append(result.Steps, BMCEnrollStep{
		Name:   "restore-cert",
		OK:     true,
		Detail: fmt.Sprintf("BMC regenerated self-signed cert: subject=%s", newCert.Subject.CommonName),
	})

	// ----------------------------------------------------------------
	// Step 2: pin-delete — remove the stored SPKI pin.
	// ----------------------------------------------------------------
	if core.pinDeleter == nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "pin-delete",
			OK:     true,
			Detail: "skipped (no TOFU pin store available)",
		})
	} else {
		if pinErr := core.pinDeleter(ctx, host, 443); pinErr != nil {
			// Non-fatal: the resolver will detect the new self-signed cert on
			// next connection and update the TOFU pin automatically.
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "pin-delete",
				OK:     false,
				Detail: fmt.Sprintf("TOFU pin delete failed (non-fatal): %v", pinErr),
			})
		} else {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "pin-delete",
				OK:     true,
				Detail: fmt.Sprintf("TOFU SPKI pin deleted for %s:443", host),
			})
		}
	}

	// Load the device before the dane-unpublish step: the enrollment
	// ceremony publishes TLSA records under the registered DNS name
	// (Device.BMCEnrollment.DNSName), not the raw BMC address, so the
	// removal must be keyed by the same name.
	dev, loadErr := core.deviceLoader(ctx, deviceID)
	if loadErr != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "device-state",
			OK:     false,
			Detail: loadErr.Error(),
		})
		return result, ErrBMCEnrollDeviceLoad{DeviceID: deviceID, Cause: loadErr}
	}
	enrolledDNSName := ""
	if dev.BMCEnrollment != nil {
		enrolledDNSName = dev.BMCEnrollment.DNSName
	}

	// ----------------------------------------------------------------
	// Step 3: dane-unpublish — remove TLSA records.
	// ----------------------------------------------------------------
	if err := runDANEUnpublishStep(ctx, result, core, enrolledDNSName, internalZone); err != nil {
		return result, err
	}

	// ----------------------------------------------------------------
	// Step 4: device-state — update Device.BMCEnrollment.
	// ----------------------------------------------------------------

	// Clear the enrollment record to reflect the restored/unenrolled state.
	// Preserve FactoryCertSHA256 for audit (it proves original identity).
	prevFactorySHA := ""
	if dev.BMCEnrollment != nil {
		prevFactorySHA = dev.BMCEnrollment.FactoryCertSHA256
	}
	dev.BMCEnrollment = &entities.BMCEnrollment{
		EnrolledAt:        time.Time{}, // zero: no active enrollment
		PinSPKISHA256:     "",          // pin removed
		DNSName:           "",          // DNS record left in place (not our responsibility to remove A record)
		TLSAPublished:     false,
		FactoryCertSHA256: prevFactorySHA, // preserve for audit
		// CertSerial and CertNotAfter are zero: platform cert is gone
	}
	dev.UpdatedAt = time.Now().UTC()

	if saveErr := core.deviceSaver(ctx, dev); saveErr != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "device-state",
			OK:     false,
			Detail: saveErr.Error(),
		})
		return result, ErrBMCEnrollDeviceSave{DeviceID: deviceID, Cause: saveErr}
	}

	result.Steps = append(result.Steps, BMCEnrollStep{
		Name:   "device-state",
		OK:     true,
		Detail: fmt.Sprintf("Device %d BMCEnrollment cleared (factory restore complete)", deviceID),
	})

	return result, nil
}

// runDANEUnpublishStep executes the dane-unpublish step. It is extracted
// so the function body stays within a readable length. Returns a non-nil
// error only for fatal failures; DANE errors are recorded as steps but
// treated as non-fatal per the same policy as enrollment.
//
// dnsName is the FQDN the enrollment ceremony published TLSA records
// under (Device.BMCEnrollment.DNSName). An empty name means enrollment
// never registered DNS, so there is nothing to unpublish.
func runDANEUnpublishStep(
	ctx context.Context,
	result *BMCRestoreResult,
	core *restoreCore,
	dnsName, internalZone string,
) error {
	if core.daneUnpublish == nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-unpublish",
			OK:     true,
			Detail: "skipped (DANE or DNS service unavailable)",
		})
		return nil
	}
	if internalZone == "" {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-unpublish",
			OK:     true,
			Detail: "skipped (no internal DNS zone configured)",
		})
		return nil
	}
	if dnsName == "" {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-unpublish",
			OK:     true,
			Detail: "skipped (no DNS name recorded in enrollment state)",
		})
		return nil
	}
	// The DANE record name uses the enrolled DNS name; strip trailing dot.
	bmcHost := strings.TrimSuffix(dnsName, ".")
	if err := core.daneUnpublish(ctx, bmcHost, 443, internalZone); err != nil {
		// Non-fatal: DANE records failing to be removed should not block
		// the rest of the cleanup; the operator can manually remove them.
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-unpublish",
			OK:     false,
			Detail: fmt.Sprintf("DANE TLSA remove failed (non-fatal): %v", err),
		})
		return nil
	}
	result.Steps = append(result.Steps, BMCEnrollStep{
		Name:   "dane-unpublish",
		OK:     true,
		Detail: fmt.Sprintf("DANE TLSA records removed for %s:443", bmcHost),
	})
	return nil
}

// DANEPublisherRemover is the narrow interface needed by the restore ceremony
// to remove TLSA records. It is satisfied by *bootstrap.DANEPublisher.
type DANEPublisherRemover interface {
	RemoveForHostname(ctx context.Context, hostname string, port uint16, zoneName string) error
}

// compile-time check.
var _ DANEPublisherRemover = (*bootstrap.DANEPublisher)(nil)
