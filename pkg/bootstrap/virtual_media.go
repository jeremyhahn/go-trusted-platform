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

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

const (
	// defaultInstallLogPollInterval is how often we re-check the HTTP
	// install-log endpoint while waiting.
	defaultInstallLogPollInterval = 10 * time.Second

	// defaultPostInstallHealthTimeout caps how long we wait for the
	// freshly-installed platformd to bind its HTTPS health endpoint
	// after the post-install power-on. The installed OS boots faster
	// than the installer itself, so this can be shorter than the
	// install-log timeout.
	defaultPostInstallHealthTimeout = 10 * time.Minute

	// powerVerifyRetries is the maximum number of PowerStatus polls
	// after a PowerOn or PowerReset command before declaring the
	// transition failed. Supermicro X10 BMCs occasionally acknowledge
	// a power command but leave the chassis unchanged.
	powerVerifyRetries = 20

	// powerVerifyInterval is the delay between consecutive PowerStatus
	// polls during post-command verification. Supermicro X10 BMCs can
	// take 30+ seconds to respond to power commands.
	powerVerifyInterval = 5 * time.Second

	// registrationFetchTimeout caps how long we wait for a single
	// registration.json fetch from the bootstrap server. This is a
	// best-effort probe so a short timeout avoids blocking the health
	// candidate list on a slow or unreachable deployer.
	registrationFetchTimeout = 5 * time.Second

	// defaultBootRetryMax is the maximum number of power-cycle retries
	// when the orchestrator detects that a node booted from disk instead
	// of the ISO. Supermicro X10 BMCs silently ignore IPMI boot-to-CD
	// flags, so if the BIOS boot order has hard disk before ATEN CDROM,
	// every SetBootDevice(CDROM) attempt is ignored. The retry mechanism
	// exists as a safety net; the operator must fix the BIOS boot order
	// for reliable virtual-media installs.
	defaultBootRetryMax = 3

	// bootProbeTimeout is how long the orchestrator waits for the
	// install log to appear after a power cycle before concluding that
	// the node booted from disk. This timeout covers POST + live-ISO
	// boot + installer reaching the "uploading log" step; on Supermicro
	// X10 hardware POST alone runs 3–5 minutes before the live kernel
	// starts, so 15 minutes gives real installs a chance to upload
	// before the orchestrator power-cycles them mid-run (which is what
	// happened with the old 3-minute value — it corrupted installs by
	// resetting the box during disk partitioning).
	bootProbeTimeout = 15 * time.Minute
)

// virtualMediaShareName is the SMB share name exposed by the bootstrap
// container's smbd (see build/docker/bootstrap/smb.conf [boot] stanza).
// The container bind-mounts the deployer-host data dir as /data and exports
// it via this share name.
const virtualMediaShareName = "boot"

// cpWebservicePort is the HTTPS port on which the control-plane webservice
// is expected to listen. It is a variable rather than a constant so tests
// can override it with the httptest.Server ephemeral port.
var cpWebservicePort = "8443"

// NodeRegistration is the JSON payload that platformd uploads to the
// bootstrap server at /installs/<hostname>/registration.json after it
// starts on a freshly-installed node. The IP field is the address
// platformd is actually listening on -- which may differ from the DHCP
// IP assigned during the installer's live environment.
type NodeRegistration struct {
	Hostname  string            `json:"hostname"`
	IP        string            `json:"ip"`
	MAC       string            `json:"mac"`
	Timestamp string            `json:"timestamp"`
	Services  map[string]string `json:"services"`
}

// ISOStager copies a local platform ISO to the bootstrap container host so
// the BMC's SMB virtual media client can fetch it. Implementations are
// transport-specific (SSH/SFTP for Linux deployers, vendor-specific for
// switch-hosted deployers, etc.). Returns the SMB URL the BMC should mount.
//
// Idempotency: implementations should compare size + modification time
// against any existing remote file and skip the upload on match. Hash
// verification is intentionally not required because computing a remote
// SHA-256 over SSH means streaming the multi-GB file back through the SSH
// channel -- wasteful for an artifact that changes rarely.
type ISOStager interface {
	StageVirtualMediaISO(ctx context.Context, localISOPath string) (smbURL string, err error)
}

// bootNodeVirtualMedia provisions a single node by mounting the platform ISO
// as virtual media on its BMC and rebooting from CD. Used when a node's
// data-plane NICs aren't reachable on the bootstrap PXE network -- only the
// BMC management interface needs L3 reachability for this path to work.
//
// Lifecycle:
//  1. Stage the platform ISO on the bootstrap container host (so the
//     container's smbd can serve it).
//  2. Connect to the BMC via the orchestrator's existing client factory.
//  3. MountVirtualMedia with the smb:// URL.
//  4. SetBootDevice(CDROM, persistent=false) -- one-shot CD boot only.
//  5. PowerReset (or PowerOn if currently off).
//  6. Wait for the installer to finish via the install log endpoint.
//     If the install log doesn't appear within bootProbeTimeout, the
//     node likely booted from disk; retry up to defaultBootRetryMax times.
//  7. After install success: unmount, set disk boot, power on, health check.
//
// On any error before step 6, attempt a best-effort unmount so we don't
// leave a phantom mount on the BMC.
func (o *Orchestrator) bootNodeVirtualMedia(ctx context.Context, node *DiscoveredNode) error {
	if o.config.ISOPath == "" && !o.SkipVirtualMediaMount {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    ErrMissingRequiredField{Field: "iso_path"},
		}
	}

	// 1. Stage the ISO on the deployer host UNLESS the operator opted out
	//    via SkipVirtualMediaMount. The skip flag exists for DCMS-locked
	//    Supermicro boards where the orchestrator's smc-cgi backend is
	//    still a stub -- operators mount via vendor tooling out-of-band
	//    and let the orchestrator handle the rest.
	var smbURL string
	if !o.SkipVirtualMediaMount {
		stager, err := newISOStager(&o.config.Deployer, o.logger)
		if err != nil {
			return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: err}
		}

		smbURL, err = stager.StageVirtualMediaISO(ctx, o.config.ISOPath)
		if err != nil {
			return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: err}
		}

		o.logger.Info("bootstrap: virtual-media: ISO staged",
			slog.String("hostname", node.Hostname),
			slog.String("smb_url", smbURL))
	} else {
		o.logger.Warn("bootstrap: virtual-media: SkipVirtualMediaMount=true, assuming media already inserted by operator",
			slog.String("hostname", node.Hostname))
	}

	// Stage per-MAC hostname so autoinstall.sh can fetch it at install
	// time and override the generic hostname baked into the shared ISO.
	// The orchestrator knows each node's target hostname (from
	// bootstrap.yaml) and all of the node's MACs (YAML + BMC-discovered).
	// Publishing under every MAC means the autoinstall hit succeeds
	// regardless of which NIC the live ISO enumerates as eth0.
	if err := o.stagePerMACHostname(ctx, node); err != nil {
		o.logger.Warn("bootstrap: virtual-media: failed to stage per-MAC hostname (install will use baked default)",
			slog.String("hostname", node.Hostname),
			slog.String("error", err.Error()))
	}

	// 2. Build the BMC client. Reuse the same factory + config builder
	//    Phase 0 uses for MAC discovery so per-node BMC settings (protocol,
	//    trust strategy, encryption key) propagate consistently.
	bmcConfig := buildBMCConfig(&node.NodeConfig, o.bmcTLSProvider)
	client, err := o.bmcFactory.NewClient(bmcConfig)
	if err != nil {
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: err}
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: BMC client close failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", closeErr.Error()))
		}
	}()

	// 3. Mount the ISO via SMB virtual media. CD/DVD media is read-only so
	//    WriteProtected is forced true. Skipped when SkipVirtualMediaMount
	//    is true (operator inserted media out-of-band).
	if !o.SkipVirtualMediaMount {
		spec := &bmc.MediaSpec{
			URL:            smbURL,
			Protocol:       bmc.MediaProtocolCIFS,
			WriteProtected: true,
		}
		if err := client.MountVirtualMedia(ctx, spec); err != nil {
			return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: err}
		}
		o.logger.Info("bootstrap: virtual-media: ISO mounted on BMC",
			slog.String("hostname", node.Hostname))

		// Register a deferred unmount so the virtual CD is ALWAYS ejected,
		// even on timeout or error. Supermicro BMCs keep the mount sticky
		// across power cycles, causing an install loop if not unmounted.
		defer func() {
			o.logger.Info("bootstrap: virtual-media: deferred unmount on exit",
				slog.String("hostname", node.Hostname))
			unmountClient, unmountErr := o.bmcFactory.NewClient(bmcConfig)
			if unmountErr != nil {
				o.logger.Warn("bootstrap: virtual-media: failed to create client for deferred unmount",
					slog.String("hostname", node.Hostname),
					slog.String("error", unmountErr.Error()))
				return
			}
			defer unmountClient.Close()
			o.bestEffortUnmount(ctx, unmountClient, node.Hostname)
		}()
	}

	// 4-6. Boot cycle with retry logic for BIOS boot order issues.
	//
	// Supermicro X10 BMCs silently ignore IPMI boot-to-CD flags. The
	// IPMI client already sends Redfish boot override as belt-and-suspenders
	// (see pkg/bmc/ipmi.go SetBootDevice), but if the BIOS boot order has
	// hard disk before ATEN CDROM, neither IPMI nor Redfish override will
	// take effect. The retry mechanism detects this by probing for the
	// install log within a short window after each power cycle. If the log
	// doesn't appear, we assume the node booted from disk and try again.
	installURL, urlErr := installLogBaseURL(&o.config.Deployer)
	if urlErr != nil {
		o.bestEffortUnmount(ctx, client, node.Hostname)
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: urlErr}
	}

	maxRetries := defaultBootRetryMax
	var logResult *InstallLogResult
	var lastBootErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		o.logger.Info("bootstrap: virtual-media: boot attempt",
			slog.String("hostname", node.Hostname),
			slog.Int("attempt", attempt),
			slog.Int("max_retries", maxRetries))

		// Re-assert the ISO mount on every attempt after the first.
		// Supermicro X10 ATEN BMCs occasionally drop the virtual CD
		// between power cycles (we've seen "CfgCD disappears after
		// reset" on firmware 1.x.x). Without re-mounting, attempt 2+
		// boots from disk because there's no media to boot from, which
		// the retry loop then misinterprets as "BIOS boot order wrong"
		// and loops forever. Explicit re-mount is a cheap idempotent
		// operation when the media is already inserted — the backend
		// short-circuits on the already-mounted path.
		if attempt > 1 && !o.SkipVirtualMediaMount {
			spec := &bmc.MediaSpec{
				URL:            smbURL,
				Protocol:       bmc.MediaProtocolCIFS,
				WriteProtected: true,
			}
			if remountErr := client.MountVirtualMedia(ctx, spec); remountErr != nil {
				o.logger.Warn("bootstrap: virtual-media: re-mount before retry failed (continuing)",
					slog.String("hostname", node.Hostname),
					slog.Int("attempt", attempt),
					slog.String("error", remountErr.Error()))
			} else {
				o.logger.Info("bootstrap: virtual-media: ISO re-asserted on BMC before retry",
					slog.String("hostname", node.Hostname),
					slog.Int("attempt", attempt))
			}
		}

		// On retries 2+, attempt to clear the host's UEFI NVRAM boot
		// entries before re-issuing the boot override. This is the X10
		// reflash trap: once the platform installer creates the
		// "Linux Boot Manager" UEFI NVRAM entry on first install, the
		// BIOS picks that entry over the BMC's one-shot CD override on
		// subsequent boots, and the retry loop spins forever booting
		// from disk. Bios.ResetBios returns NVRAM to defaults so the
		// override has no on-disk competitor.
		//
		// We only invoke this on attempt >=2 so a fresh node never gets
		// its BIOS attributes reset unnecessarily. Failure is non-fatal
		// — many BMCs (notably older Supermicro X10 firmware) do not
		// expose Bios.ResetBios, in which case ErrUEFIBootClearUnsupported
		// is returned and the loop continues to rely on the override
		// alone (Fix C will add a vendor CGI fallback for that case).
		if attempt > 1 {
			if clearErr := client.ClearUEFIBootEntries(ctx); clearErr != nil {
				o.logger.Warn("bootstrap: virtual-media: pre-retry NVRAM clear failed (continuing)",
					slog.String("hostname", node.Hostname),
					slog.Int("attempt", attempt),
					slog.String("error", clearErr.Error()))
			} else {
				o.logger.Info("bootstrap: virtual-media: cleared UEFI NVRAM boot entries before retry",
					slog.String("hostname", node.Hostname),
					slog.Int("attempt", attempt))
			}
		}

		// Set boot device to CD/DVD, one-shot only. BMC auto-clears
		// after it honors the override, so this must be re-issued on
		// every attempt.
		if err := client.SetBootDevice(ctx, bmc.BootDeviceCDROM, false); err != nil {
			// Close stale session and retry with fresh client for next attempt.
			client.Close()
			freshClient, freshErr := o.bmcFactory.NewClient(bmcConfig)
			if freshErr != nil {
				return ErrBootDeviceSetFailed{
					Hostname: node.Hostname,
					Device:   string(bmc.BootDeviceCDROM),
					Cause:    err,
				}
			}
			client = freshClient
			if retryErr := client.SetBootDevice(ctx, bmc.BootDeviceCDROM, false); retryErr != nil {
				return ErrBootDeviceSetFailed{
					Hostname: node.Hostname,
					Device:   string(bmc.BootDeviceCDROM),
					Cause:    retryErr,
				}
			}
		}

		// Record the install-attempt timestamp BEFORE triggering the power
		// cycle so the install-log poller can reject stale logs.
		installStart := time.Now()

		// Power-cycle: PowerReset if on, PowerOn if off.
		if powerErr := o.powerCycleNode(ctx, client, bmcConfig, node.Hostname); powerErr != nil {
			return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: powerErr}
		}

		// Verify the server reached PowerStateOn.
		client.Close()
		verifyClient, verifyErr := o.bmcFactory.NewClient(bmcConfig)
		if verifyErr != nil {
			return ErrPowerControlFailed{
				Hostname:  node.Hostname,
				Operation: "verify-reconnect",
				Cause:     verifyErr,
			}
		}

		verified, lastState := o.verifyPowerOn(ctx, verifyClient, node.Hostname)
		verifyClient.Close()

		if !verified {
			o.bestEffortUnmount(ctx, client, node.Hostname)
			return ErrPowerStateVerificationFailed{
				Hostname: node.Hostname,
				Expected: string(bmc.PowerStateOn),
				Actual:   string(lastState),
				Retries:  powerVerifyRetries,
			}
		}

		// Probe for the install log with a short timeout. If it doesn't
		// appear, the node probably booted from disk instead of the ISO.
		probeCtx, probeCancel := context.WithTimeout(ctx, bootProbeTimeout)
		poller := &InstallLogPoller{
			BaseURL:  installURL,
			Hostname: sanitizeHostnameForInstallPath(node.Hostname),
			MACs:     allNodeMACs(node),
			Since:    installStart,
			Interval: defaultInstallLogPollInterval,
			Logger:   o.logger,
		}

		logResult, lastBootErr = poller.Wait(probeCtx)
		probeCancel()

		if lastBootErr == nil && logResult != nil && logResult.Found {
			// Install log appeared -- the ISO booted successfully.
			break
		}

		// Install log didn't appear within the probe window. If this was
		// the last retry, fall through to the error path below.
		if attempt < maxRetries {
			o.logger.Warn("bootstrap: virtual-media: install log not found within probe window, node likely booted from disk",
				slog.String("hostname", node.Hostname),
				slog.Int("attempt", attempt),
				slog.Duration("probe_timeout", bootProbeTimeout))

			// Reconnect BMC client for next retry cycle.
			freshClient, freshErr := o.bmcFactory.NewClient(bmcConfig)
			if freshErr != nil {
				return ErrVirtualMediaBootFailed{
					Hostname: node.Hostname,
					Cause:    ErrBMCReconnect{Hostname: node.Hostname, Operation: "boot-retry", Cause: freshErr},
				}
			}
			client = freshClient
			continue
		}
	}

	// If we exhausted all retries without seeing an install log, fail.
	if logResult == nil || !logResult.Found {
		logURL := installURL + "/installs/" + node.Hostname + "/install.log"
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause: ErrBootRetryExhausted{
				Hostname:   node.Hostname,
				MaxRetries: maxRetries,
				Cause:      ErrInstallLogNotFound{Hostname: node.Hostname, URL: logURL, Cause: lastBootErr},
			},
		}
	}

	// Check the install log result for success/failure.
	if !logResult.Success() {
		logURL := installURL + "/installs/" + node.Hostname + "/install.log"
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    ErrInstallFailed{Hostname: node.Hostname, ExitCode: logResult.ExitCode, LogURL: logURL},
		}
	}
	o.logger.Info("bootstrap: virtual-media: installer reported success",
		slog.String("hostname", node.Hostname),
		slog.Int("exit_code", logResult.ExitCode),
		slog.Int("log_bytes", len(logResult.Raw)))

	// Register a deferred power-on so the server is ALWAYS powered on
	// when this function exits, even if post-install steps fail.
	defer func() {
		o.deferredPowerOn(ctx, bmcConfig, node.Hostname)
	}()

	// 7. Post-install: unmount, set disk boot, power on, health check.
	//    Open a fresh BMC client since the previous session timed out
	//    during the install wait (potentially 20+ minutes).
	postClient, postErr := o.bmcFactory.NewClient(bmcConfig)
	if postErr != nil {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    ErrBMCReconnect{Hostname: node.Hostname, Operation: "post-install ops", Cause: postErr},
		}
	}
	defer func() {
		if closeErr := postClient.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: post-install BMC client close failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", closeErr.Error()))
		}
	}()

	// Unmount the virtual CD BEFORE cycling into the installed OS so
	// the BIOS doesn't try to re-boot into the installer on the next reset.
	o.logger.Info("bootstrap: virtual-media: unmounting virtual CD",
		slog.String("hostname", node.Hostname))
	o.bestEffortUnmount(ctx, postClient, node.Hostname)

	// Switch to persistent disk boot.
	if err := postClient.SetBootDevice(ctx, bmc.BootDeviceDisk, true); err != nil {
		return ErrBootDeviceSetFailed{
			Hostname: node.Hostname,
			Device:   string(bmc.BootDeviceDisk),
			Cause:    err,
		}
	}

	// Power the host back on from disk.
	if powerErr := o.postInstallPowerOn(ctx, postClient, bmcConfig, node.Hostname); powerErr != nil {
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: powerErr}
	}

	// Wait for the newly-installed platformd health endpoint.
	healthAddrs := candidateHealthAddresses(node, logResult, installURL)
	if len(healthAddrs) == 0 {
		o.logger.Warn("bootstrap: virtual-media: no usable health addresses after install, skipping health wait",
			slog.String("hostname", node.Hostname))
		return nil
	}
	healthCtx, healthCancel := context.WithTimeout(ctx, defaultPostInstallHealthTimeout)
	defer healthCancel()
	if healthErr := o.waitForHealthAny(healthCtx, healthAddrs, installURL, node.Hostname, allNodeMACs(node)); healthErr != nil {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    ErrHealthCheckFailed{Address: strings.Join(healthAddrs, ","), Cause: healthErr},
		}
	}
	return nil
}

// powerCycleNode performs a cold power cycle: explicit power-off, poll
// until the BMC reports the chassis is off, then power-on. This is more
// reliable than a single PowerReset on Supermicro X10 BMCs, where:
//
//   - chassis power cycle (IPMI 0x02) is a soft request that the running
//     OS can refuse via ACPI; the BMC silently no-ops with no chassis
//     transition (Last Power Event empty), and PowerStatus keeps
//     returning "on" while the OS continues running.
//   - chassis power reset (IPMI 0x03) does reboot the chassis, but the
//     BMC clears the boot-override flag immediately on reset, so when
//     the BIOS POSTs it sees no override and falls through to the
//     existing disk install instead of the virtual-media CD.
//
// An explicit off → poll-until-off → on sequence forces a clean cold
// boot that the BIOS POSTs through with the boot-override flag still
// valid. Verified working on X10SDV-TP8F for Trusted Platform installer
// virtual-media boot. Other vendors honor PowerReset correctly but
// off-on is universally more reliable, so we use it everywhere rather
// than a quirk-keyed branch.
func (o *Orchestrator) powerCycleNode(ctx context.Context, client bmc.Client, bmcConfig *bmc.Config, hostname string) error {
	state, err := client.PowerStatus(ctx)
	if err != nil {
		return ErrPowerControlFailed{Hostname: hostname, Operation: "status", Cause: err}
	}
	if state != bmc.PowerStateOff {
		if err := client.PowerOff(ctx); err != nil {
			return ErrPowerControlFailed{Hostname: hostname, Operation: "off", Cause: err}
		}
		if err := o.waitForPowerOff(ctx, client, hostname); err != nil {
			return err
		}
	}
	if err := client.PowerOn(ctx); err != nil {
		return ErrPowerControlFailed{Hostname: hostname, Operation: "on", Cause: err}
	}
	o.logger.Info("bootstrap: virtual-media: cold power cycle issued",
		slog.String("hostname", hostname),
		slog.String("previous_state", string(state)))
	return nil
}

// waitForPowerOff polls PowerStatus until the BMC reports the chassis is
// off, or returns ErrPowerControlFailed when powerVerifyRetries is
// exhausted. Used by powerCycleNode between PowerOff and PowerOn so we
// don't issue PowerOn while the chassis is still transitioning.
func (o *Orchestrator) waitForPowerOff(ctx context.Context, client bmc.Client, hostname string) error {
	ticker := time.NewTicker(powerVerifyInterval)
	defer ticker.Stop()
	for attempt := 0; attempt < powerVerifyRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ErrPowerControlFailed{Hostname: hostname, Operation: "off-verify", Cause: ctx.Err()}
		case <-ticker.C:
		}
		st, err := client.PowerStatus(ctx)
		if err != nil {
			o.logger.Warn("bootstrap: virtual-media: power-off verify poll failed",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt+1),
				slog.String("error", err.Error()))
			continue
		}
		if st == bmc.PowerStateOff {
			o.logger.Info("bootstrap: virtual-media: power state verified off",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt+1))
			return nil
		}
	}
	return ErrPowerControlFailed{
		Hostname:  hostname,
		Operation: "off-verify",
		Cause:     fmt.Errorf("chassis still on after %d polls", powerVerifyRetries),
	}
}

// verifyPowerOn polls PowerStatus until the server is on or retries are exhausted.
// Returns (true, lastState) if verified, (false, lastState) otherwise.
//
// When the BMC reports PowerStateOff for several consecutive polls after a
// prior power-cycle command, we re-issue PowerOn. X10 BMCs sometimes
// miss or no-op a PowerReset when the host was actually off (e.g. we
// raced a manual poweroff or the reset landed mid-transition), leaving
// the node stuck at off until an explicit PowerOn. Re-issuing the PowerOn
// every few polls is a cheap idempotent nudge: if the host is already
// booting, the BMC ignores duplicate ons; if it's stuck off, this
// unsticks it.
func (o *Orchestrator) verifyPowerOn(ctx context.Context, client bmc.Client, hostname string) (bool, bmc.PowerState) {
	ticker := time.NewTicker(powerVerifyInterval)
	defer ticker.Stop()

	var lastState bmc.PowerState
	offStreak := 0
	for attempt := 0; attempt < powerVerifyRetries; attempt++ {
		select {
		case <-ctx.Done():
			return false, lastState
		case <-ticker.C:
		}
		st, err := client.PowerStatus(ctx)
		if err != nil {
			o.logger.Warn("bootstrap: virtual-media: power verify poll failed",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt+1),
				slog.String("error", err.Error()))
			continue
		}
		lastState = st
		if st == bmc.PowerStateOn {
			o.logger.Info("bootstrap: virtual-media: power state verified on",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt+1))
			return true, st
		}
		o.logger.Warn("bootstrap: virtual-media: power state not yet on",
			slog.String("hostname", hostname),
			slog.Int("attempt", attempt+1),
			slog.String("state", string(st)))
		// Stuck-off recovery: after ~15s of consecutive off reports,
		// re-issue PowerOn. X10 BMCs can drop a PowerReset when the
		// host was off-by-race; an explicit on unsticks them. Repeat
		// every 3 intervals so we try ~3 more times within the retry
		// budget before giving up.
		if st == bmc.PowerStateOff {
			offStreak++
			if offStreak >= 3 && offStreak%3 == 0 {
				if onErr := client.PowerOn(ctx); onErr != nil {
					o.logger.Warn("bootstrap: virtual-media: stuck-off PowerOn retry failed",
						slog.String("hostname", hostname),
						slog.Int("attempt", attempt+1),
						slog.String("error", onErr.Error()))
				} else {
					o.logger.Info("bootstrap: virtual-media: re-issued PowerOn on stuck-off host",
						slog.String("hostname", hostname),
						slog.Int("attempt", attempt+1))
				}
			}
		} else {
			offStreak = 0
		}
	}
	return false, lastState
}

// postInstallPowerOn handles the power-on sequence after a successful install.
// The installer calls `poweroff` at the end, so the node is typically at S5.
func (o *Orchestrator) postInstallPowerOn(ctx context.Context, client bmc.Client, bmcConfig *bmc.Config, hostname string) error {
	postState, err := client.PowerStatus(ctx)
	if err != nil {
		return ErrPowerControlFailed{Hostname: hostname, Operation: "status", Cause: err}
	}
	switch postState {
	case bmc.PowerStateOff:
		o.logger.Info("bootstrap: virtual-media: host at S5 after install, powering on for first-boot",
			slog.String("hostname", hostname))
		if err := client.PowerOn(ctx); err != nil {
			return ErrPowerControlFailed{Hostname: hostname, Operation: "on", Cause: err}
		}
	case bmc.PowerStateOn:
		o.logger.Info("bootstrap: virtual-media: host still on after install, resetting for first-boot",
			slog.String("hostname", hostname))
		if err := client.PowerReset(ctx); err != nil {
			return ErrPowerControlFailed{Hostname: hostname, Operation: "reset", Cause: err}
		}
	default:
		o.logger.Warn("bootstrap: virtual-media: unknown power state after install",
			slog.String("hostname", hostname),
			slog.String("state", string(postState)))
	}

	// Verify the host reached PowerStateOn after the post-install power command.
	o.logger.Info("bootstrap: virtual-media: verifying post-install power state",
		slog.String("hostname", hostname))
	client.Close()

	postVerifyClient, postVerifyErr := o.bmcFactory.NewClient(bmcConfig)
	if postVerifyErr != nil {
		return ErrBMCReconnect{Hostname: hostname, Operation: "post-install power verify", Cause: postVerifyErr}
	}
	defer postVerifyClient.Close()

	postVerifyTicker := time.NewTicker(powerVerifyInterval)
	defer postVerifyTicker.Stop()

	postVerified := false
	for attempt := 1; attempt <= powerVerifyRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ErrPowerControlFailed{Hostname: hostname, Operation: "post-install-verify", Cause: ctx.Err()}
		case <-postVerifyTicker.C:
		}
		st, stErr := postVerifyClient.PowerStatus(ctx)
		if stErr != nil {
			o.logger.Warn("bootstrap: virtual-media: post-install power status check failed",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt),
				slog.String("error", stErr.Error()))
			continue
		}
		if st == bmc.PowerStateOn {
			o.logger.Info("bootstrap: virtual-media: post-install power state verified on",
				slog.String("hostname", hostname),
				slog.Int("attempt", attempt))
			postVerified = true
			break
		}
		o.logger.Warn("bootstrap: virtual-media: post-install power state not yet on, retrying",
			slog.String("hostname", hostname),
			slog.Int("attempt", attempt),
			slog.String("state", string(st)))
		// Retry power on if still off.
		if st == bmc.PowerStateOff {
			_ = postVerifyClient.PowerOn(ctx)
		}
	}
	if !postVerified {
		return ErrPowerStateVerificationFailed{
			Hostname: hostname,
			Expected: string(bmc.PowerStateOn),
			Actual:   string(bmc.PowerStateOff),
			Retries:  powerVerifyRetries,
		}
	}
	return nil
}

// deferredPowerOn ensures the server is powered on when the function exits.
// It opens a fresh BMC client (the caller's may have timed out after a long
// install wait), checks the power state, and issues a PowerOn if the server
// is off. All errors are logged but not propagated -- this is a best-effort
// safety net, not a flow-control mechanism.
func (o *Orchestrator) deferredPowerOn(ctx context.Context, bmcConfig *bmc.Config, hostname string) {
	o.logger.Info("bootstrap: virtual-media: deferred power-on check on exit",
		slog.String("hostname", hostname))

	powerClient, powerErr := o.bmcFactory.NewClient(bmcConfig)
	if powerErr != nil {
		o.logger.Warn("bootstrap: virtual-media: failed to create BMC client for deferred power-on",
			slog.String("hostname", hostname),
			slog.String("error", powerErr.Error()))
		return
	}
	defer func() {
		if closeErr := powerClient.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: deferred power-on BMC client close failed",
				slog.String("hostname", hostname),
				slog.String("error", closeErr.Error()))
		}
	}()

	st, stErr := powerClient.PowerStatus(ctx)
	if stErr != nil {
		o.logger.Warn("bootstrap: virtual-media: deferred power-on status check failed",
			slog.String("hostname", hostname),
			slog.String("error", stErr.Error()))
		return
	}
	if st == bmc.PowerStateOn {
		o.logger.Info("bootstrap: virtual-media: deferred power-on: server already on",
			slog.String("hostname", hostname))
		return
	}

	o.logger.Info("bootstrap: virtual-media: deferred power-on: server is off, powering on",
		slog.String("hostname", hostname),
		slog.String("state", string(st)))
	if onErr := powerClient.PowerOn(ctx); onErr != nil {
		o.logger.Warn("bootstrap: virtual-media: deferred power-on failed",
			slog.String("hostname", hostname),
			slog.String("error", onErr.Error()))
	}
}

// waitForHealthAny polls every candidate address until ONE of them
// returns a healthy response or the context expires. On each tick it
// also re-reads registration.json from the bootstrap server so it
// picks up the node's actual post-DHCP IP as soon as platformd
// uploads it (which happens after the first-boot networking is up).
func (o *Orchestrator) waitForHealthAny(ctx context.Context, addresses []string, registrationBaseURL string, hostname string, macs []string) error {
	if len(addresses) == 0 && registrationBaseURL == "" {
		return fmt.Errorf("no health addresses to check")
	}
	ticker := time.NewTicker(defaultHealthInterval)
	defer ticker.Stop()

	seen := make(map[string]struct{})
	for _, a := range addresses {
		seen[a] = struct{}{}
	}

	for {
		// Re-read registration.json on each tick to pick up new IP.
		// MAC-keyed path is tried before hostname to tolerate shared
		// ISOs that bake a generic hostname.
		if registrationBaseURL != "" && (hostname != "" || len(macs) > 0) {
			if regIP, fetchErr := fetchRegistrationIP(registrationBaseURL, hostname, macs); fetchErr == nil {
				if _, already := seen[regIP]; !already {
					o.logger.Info("bootstrap: virtual-media: discovered new IP from registration",
						slog.String("ip", regIP))
					addresses = append([]string{regIP}, addresses...)
					seen[regIP] = struct{}{}
				}
			}
		}

		for _, addr := range addresses {
			if err := o.healthChk.Check(ctx, addr); err == nil {
				o.logger.Info("bootstrap: virtual-media: health endpoint responded",
					slog.String("address", addr))
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// candidateHealthAddresses returns the list of addresses the orchestrator
// should try when waiting for an installed node's health endpoint. Order
// matters -- the first address that responds wins.
//
// When registrationBaseURL is non-empty the function first attempts a
// best-effort fetch of registration.json from the bootstrap server. The
// IP in that file is the address platformd is actually listening on after
// the installed OS obtained a (possibly different) DHCP lease. That IP
// is inserted as the first candidate because it is the most likely to be
// correct.
//
// Remaining candidates follow in decreasing likelihood: hostname (DNS may
// work in production), BMC address (flat homelab fallback), and any
// DHCP-assigned IPs scraped from the install log's postmortem block.
func candidateHealthAddresses(node *DiscoveredNode, logResult *InstallLogResult, registrationBaseURL string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	// Registration IP first -- platformd uploads this after first-boot
	// with its actual post-DHCP address. The fetcher tries MAC-keyed
	// path(s) first then falls back to the hostname path, because
	// shared ISOs bake a generic hostname like "server" that doesn't
	// match the per-node hostname in bootstrap.yaml. MAC is the only
	// identity both ends agree on without per-node ISO customization.
	// Best-effort: if the fetch fails we fall through to the existing
	// heuristic candidates.
	if registrationBaseURL != "" {
		if regIP, fetchErr := fetchRegistrationIP(registrationBaseURL, node.Hostname, allNodeMACs(node)); fetchErr == nil {
			add(regIP)
		}
	}

	// Static IPs declared in the node's overrides. An operator who pins
	// a node to a specific IPv4 address in bootstrap.yaml's
	// `overrides.network.interfaces[].ipv4-address` is asserting
	// "this is where platformd will listen" -- so it belongs near
	// the top of the candidate list. Strips any "/24" CIDR suffix
	// so the result is a dotted quad suitable for httpHealthChecker.
	for _, ip := range staticIPsFromOverrides(node.Overrides) {
		add(ip)
	}
	// Hostname -- DNS may be available for production deployments.
	add(node.Hostname)
	// BMC address is a LAST resort: only useful if the operator placed
	// the node on the same L2 as the BMC. It's commonly wrong but
	// sometimes the only thing that works in flat homelab networks.
	add(node.BMCAddress)
	// Install log may carry a dhcp-assigned IP in the postmortem block.
	if logResult != nil && logResult.Raw != "" {
		for _, line := range strings.Split(logResult.Raw, "\n") {
			trimmed := strings.TrimSpace(line)
			// Match "inet 192.168.X.Y/24" lines from the `ip addr`
			// dump embedded in the postmortem manifest. These give
			// us the host's real DHCP-assigned IPs.
			if !strings.HasPrefix(trimmed, "inet ") {
				continue
			}
			rest := strings.TrimPrefix(trimmed, "inet ")
			slash := strings.Index(rest, "/")
			if slash < 0 {
				continue
			}
			ip := rest[:slash]
			// Skip localhost and link-local.
			if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "169.254.") {
				continue
			}
			add(ip)
		}
	}
	return out
}

// fetchRegistrationIP fetches the node's registration.json from the
// bootstrap server and returns the IP field. URLs are tried in order:
//
//  1. /installs/mac/<normalized-mac>/registration.json   (one per known MAC)
//  2. /installs/<sanitized-hostname>/registration.json   (fallback)
//
// The MAC path is tried first because shared ISOs bake a generic
// hostname (e.g. "server") that doesn't match the orchestrator's
// per-node hostname in bootstrap.yaml. MAC is the only identity both
// sides agree on without per-node ISO customization.
//
// Returns a typed ErrRegistrationFetch on failure of ALL candidate
// URLs (HTTP error, non-200 status, JSON decode error, or empty IP
// field). Success on any single URL wins immediately.
func fetchRegistrationIP(baseURL, hostname string, macs []string) (string, error) {
	client := &http.Client{Timeout: registrationFetchTimeout}

	urls := make([]string, 0, len(macs)+1)
	for _, m := range macs {
		if sanitized := sanitizeMACForPath(m); sanitized != "" {
			urls = append(urls, baseURL+"/installs/mac/"+sanitized+"/registration.json")
		}
	}
	if hostname != "" {
		sanitized := sanitizeHostnameForInstallPath(hostname)
		urls = append(urls, baseURL+"/installs/"+sanitized+"/registration.json")
	}

	var lastErr error
	for _, regURL := range urls {
		ip, err := fetchRegistrationIPOnce(client, regURL)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no registration URLs to try")
	}
	return "", lastErr
}

// fetchRegistrationIPOnce performs a single GET of a registration.json
// URL and extracts the IP field.
func fetchRegistrationIPOnce(client *http.Client, regURL string) (string, error) {
	resp, err := client.Get(regURL)
	if err != nil {
		return "", ErrRegistrationFetch{URL: regURL, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrRegistrationFetch{
			URL:   regURL,
			Cause: fmt.Errorf("unexpected status %d", resp.StatusCode),
		}
	}

	// Cap the read to 64 KiB -- registration.json is a small document
	// and this prevents a misbehaving server from filling memory.
	const maxBody = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", ErrRegistrationFetch{URL: regURL, Cause: err}
	}

	var reg NodeRegistration
	if err := json.Unmarshal(body, &reg); err != nil {
		return "", ErrRegistrationFetch{URL: regURL, Cause: err}
	}

	ip := strings.TrimSpace(reg.IP)
	if ip == "" {
		return "", ErrRegistrationFetch{
			URL:   regURL,
			Cause: fmt.Errorf("registration.json has empty ip field"),
		}
	}
	return ip, nil
}

// installLogBaseURL returns the HTTP base URL of the bootstrap container's
// forensic sink for the deployer host. Falls back to :8080 when the
// deployer config doesn't carry an explicit port.
func installLogBaseURL(dep *DeployerConfig) (string, error) {
	if dep == nil || dep.Host == "" {
		return "", ErrMissingRequiredField{Field: "deployer.host"}
	}
	// Prefer the SMB host (on-bootstrap-net IP) over the management
	// host because the bootstrap container's HTTP sink is bound to
	// the provisioning interface, which is the same IP the installer
	// uses to reach it.
	host := dep.SMBHost
	if host == "" {
		host = dep.Host
	}
	return "http://" + host + ":8080", nil
}

// stagePerMACHostname publishes the node's hostname AND merged installer
// config to the pxeboot HTTP config server under every known MAC.
//
// This implements the orchestrator side of the dynamic config-delivery
// architecture documented in:
//   - docs/architecture/bootstrap-flow.md §6 (per-MAC keying)
//   - docs/bootstrap/config-delivery.md §5 (what the orchestrator publishes)
//   - docs/ipxe/architecture.md (HTTP endpoint contract)
//
// For each MAC in union(node.MACs, BMC-discovered MACs):
//
//	PUT  /config/mac/<mac>/hostname        = node.Hostname
//	PUT  /config/mac/<mac>/installer.yaml  = merged device config (if resolvable)
//
// autoinstall.sh reads both at install time (customize.go Priority 1 +
// resolve_platform_hostname). Publishing under every MAC ensures the
// installer finds its config on whichever NIC the live environment
// enumerates as eth0 on multi-NIC hosts.
//
// If the per-node merged config can't be resolved (template missing,
// overrides_file path wrong, merge error) the function still publishes
// hostname and logs a warning rather than failing the whole install —
// the node falls back to whatever config is baked into the ISO.
func (o *Orchestrator) stagePerMACHostname(ctx context.Context, node *DiscoveredNode) error {
	if node == nil || strings.TrimSpace(node.Hostname) == "" {
		return nil
	}
	baseURL, err := installLogBaseURL(&o.config.Deployer)
	if err != nil {
		return err
	}
	macs := allNodeMACs(node)
	if len(macs) == 0 {
		return nil
	}

	// Resolve the merged per-node config once, upfront. A resolve
	// failure logs and falls through to hostname-only staging so a
	// template bug doesn't block the install entirely.
	var mergedConfig string
	if resolved, resolveErr := o.resolveNodeConfig(node.Hostname, node.Role); resolveErr != nil {
		o.logger.Warn("bootstrap: virtual-media: could not resolve per-node config, staging hostname only",
			slog.String("hostname", node.Hostname),
			slog.String("error", resolveErr.Error()))
	} else {
		mergedConfig = resolved
	}

	// For client nodes (gateway, compute, worker) fetch the control
	// plane's CA bundle and stage it alongside the per-MAC config so
	// the installer can add it to the OS trust store before first
	// ACME enrollment. Without this, the client's first HTTPS
	// connection to `https://<cp>:9443/api/v1/acme/directory` fails
	// with "x509: certificate signed by unknown authority".
	//
	// The CP node itself doesn't need this — it issues its own CA.
	//
	// In addition to the bundle, capture the CP webservice TLS leaf's
	// SPKI SHA-256 pin so the autoinstall can fall back to the SPKI
	// bootstrap-trust strategy if the bundle delivery path fails (e.g.
	// the orchestrator's pxeboot HTTP endpoint is unreachable from the
	// new node). Both delivery paths are independent: bundle → embedded
	// strategy, pin → spki strategy. The auto strategy walks both.
	var caBundle string
	var spkiPin string
	if node.Role != RoleControlPlane {
		if bundle, bundleErr := o.fetchControlPlaneCABundle(ctx); bundleErr != nil {
			o.logger.Warn("bootstrap: virtual-media: could not fetch CP CA bundle, client will fall back to trust bootstrap",
				slog.String("hostname", node.Hostname),
				slog.String("error", bundleErr.Error()))
		} else {
			caBundle = bundle
		}
		if pin, pinErr := o.fetchControlPlaneSPKIPin(ctx); pinErr != nil {
			o.logger.Warn("bootstrap: virtual-media: could not capture CP SPKI pin",
				slog.String("hostname", node.Hostname),
				slog.String("error", pinErr.Error()))
		} else {
			spkiPin = pin
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var firstErr error
	stagedHostname := 0
	stagedConfig := 0
	stagedCA := 0
	stagedSPKI := 0
	for _, m := range macs {
		sanitized := sanitizeMACForPath(m)
		if sanitized == "" {
			continue
		}
		if err := o.stageConfigValue(ctx, client, baseURL, sanitized, "hostname", node.Hostname, "text/plain; charset=utf-8"); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			stagedHostname++
		}
		if mergedConfig != "" {
			if err := o.stageConfigValue(ctx, client, baseURL, sanitized, "installer.yaml", mergedConfig, "application/yaml"); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				stagedConfig++
			}
		}
		if caBundle != "" {
			if err := o.stageConfigValue(ctx, client, baseURL, sanitized, "ca-bundle.pem", caBundle, "application/x-pem-file"); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				stagedCA++
			}
		}
		if spkiPin != "" {
			if err := o.stageConfigValue(ctx, client, baseURL, sanitized, "bootstrap-spki-pin", spkiPin, "text/plain; charset=utf-8"); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				stagedSPKI++
			}
		}
	}
	o.logger.Info("bootstrap: virtual-media: staged per-MAC config",
		slog.String("hostname", node.Hostname),
		slog.Int("macs_total", len(macs)),
		slog.Int("hostname_staged", stagedHostname),
		slog.Int("config_staged", stagedConfig),
		slog.Int("config_bytes", len(mergedConfig)),
		slog.Int("ca_staged", stagedCA),
		slog.Int("ca_bytes", len(caBundle)),
		slog.Int("spki_staged", stagedSPKI),
		slog.Bool("spki_captured", spkiPin != ""))
	if stagedHostname == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

// stageConfigValue PUTs a single key/value to the pxeboot
// /config/mac/<mac>/<key> endpoint.
func (o *Orchestrator) stageConfigValue(ctx context.Context, client *http.Client, baseURL, mac, key, value, contentType string) error {
	url := baseURL + "/config/mac/" + mac + "/" + key
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(value))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: status %d", url, resp.StatusCode)
	}
	return nil
}

// allNodeMACs returns the union of a node's YAML-declared MACs and any
// MACs discovered via BMC enumeration. Multi-NIC hosts expose more MACs
// to the BMC than operators typically list in bootstrap.yaml, and the
// installer's autoinstall.sh picks /sys/class/net/eth0 — which is often
// a different MAC than the one pinned in config. Passing the union to
// the install-log poller, registration fetcher, and health checker
// lets the orchestrator correlate regardless of which NIC came up
// first in the live-ISO environment.
func allNodeMACs(node *DiscoveredNode) []string {
	seen := make(map[string]struct{}, len(node.MACs)+len(node.DiscoveredMACs))
	out := make([]string, 0, len(node.MACs)+len(node.DiscoveredMACs))
	add := func(m string) {
		m = strings.TrimSpace(m)
		if m == "" {
			return
		}
		if _, ok := seen[strings.ToLower(m)]; ok {
			return
		}
		seen[strings.ToLower(m)] = struct{}{}
		out = append(out, m)
	}
	for _, m := range node.MACs {
		add(m)
	}
	for _, m := range node.DiscoveredMACs {
		add(m)
	}
	return out
}

// sanitizeHostnameForInstallPath mirrors the sanitization the ISO
// customizer applies when baking platform_hostname=<value> into the
// kernel cmdline. Must stay in lockstep with
// pkg/iso/customize.go::sanitizeHostnameForPath.
func sanitizeHostnameForInstallPath(hostname string) string {
	var b strings.Builder
	b.Grow(len(hostname))
	for _, r := range strings.ToLower(hostname) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// bestEffortUnmount attempts to eject virtual media without failing the
// surrounding flow. Used both on the success path (post-install cleanup)
// and on every error path between mount and health to avoid leaving a
// phantom mount on the BMC.
func (o *Orchestrator) bestEffortUnmount(ctx context.Context, client bmc.Client, hostname string) {
	if err := client.UnmountVirtualMedia(ctx); err != nil {
		o.logger.Warn("bootstrap: virtual-media: unmount failed (best-effort)",
			slog.String("hostname", hostname),
			slog.String("error", err.Error()))
	}
}

// virtualMediaSMBURL builds the canonical smb:// URL for an ISO that lives
// on the deployer host's data directory. The host part comes from the
// bootstrap config's deployer.host, the share name is the constant exposed
// by the container's smb.conf, and the file name is the basename of the
// local path. Exposed for tests.
func virtualMediaSMBURL(deployerHost, localISOPath string) string {
	return "smb://" + deployerHost + "/" + virtualMediaShareName + "/" + filepath.Base(localISOPath)
}

// staticIPsFromOverrides walks the node's inline override map looking for
// `network.interfaces[].ipv4-address` entries and returns the dotted-quad
// portion (any `/<prefix>` suffix stripped). Used by candidateHealthAddresses
// so the operator-declared static IP is probed before falling back to
// hostname/BMC/DHCP-scraped candidates.
//
// The overrides map is the deep-merged result of inline `overrides:` +
// `overrides_file:`. This helper reads ONLY the inline map because the
// orchestrator loads that directly; the file-merged form is applied at
// staging time but doesn't flow back into NodeConfig.Overrides on the
// health-probe code path. That's acceptable here because static IPs are
// typically declared inline (they're per-node, not per-role).
//
// Returns an empty slice on any missing/wrong-typed field rather than an
// error so callers can simply range over the result.
func staticIPsFromOverrides(overrides map[string]interface{}) []string {
	if overrides == nil {
		return nil
	}
	net, ok := overrides["network"].(map[string]interface{})
	if !ok {
		return nil
	}
	ifaces, ok := net["interfaces"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, raw := range ifaces {
		iface, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		addr, ok := iface["ipv4-address"].(string)
		if !ok || addr == "" {
			continue
		}
		// Strip CIDR suffix if present ("198.18.1.140/24" -> "198.18.1.140").
		if slash := strings.Index(addr, "/"); slash > 0 {
			addr = addr[:slash]
		}
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// fetchControlPlaneCABundle GETs the control plane's CA bundle PEM
// from its ACME endpoint and performs capture-then-verify: the certs
// in the returned bundle are cross-checked against the CA chain seen
// in the TLS handshake so that a MITM substituting a foreign bundle
// is detected. On success the parsed CA pool is stored in cpCAPool
// for use by subsequent TLS calls (fetchControlPlaneSPKIPin,
// ControlPlaneCAPool).
//
// The initial TLS connection uses InsecureSkipVerify — intentional,
// because the CA we're fetching IS the trust anchor. The
// capture-then-verify step restores the security guarantee: the
// body is only trusted when it is signed by the same issuer that
// presented the TLS certificate.
func (o *Orchestrator) fetchControlPlaneCABundle(ctx context.Context) (string, error) {
	var cpNode *DiscoveredNode
	for i := range o.discovered {
		if o.discovered[i].Role == RoleControlPlane {
			cpNode = &o.discovered[i]
			break
		}
	}
	if cpNode == nil {
		return "", fmt.Errorf("no control-plane node discovered")
	}

	cpIPs := staticIPsFromOverrides(cpNode.Overrides)
	if len(cpIPs) == 0 {
		return "", fmt.Errorf("control-plane node has no static IP override")
	}

	// Step 1: open a raw TLS connection to capture the peer chain
	// before the HTTP GET, so we have the handshake anchor available
	// for the verify step regardless of HTTP redirect behaviour.
	addr := cpIPs[0] + ":" + cpWebservicePort
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // bootstrap trust anchor capture
	})
	if err != nil {
		return "", fmt.Errorf("CP TLS dial %s: %w", addr, err)
	}
	peerChain := conn.ConnectionState().PeerCertificates
	conn.Close()

	// Step 2: fetch the bundle over HTTPS (InsecureSkipVerify; we verify below).
	url := "https://" + addr + "/api/v1/acme/ca-bundle"
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // bootstrap trust anchor fetch
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Step 3: parse the returned PEM bundle.
	pool, bundleCerts, err := parseCAPEMBundle(body)
	if err != nil {
		return "", err
	}

	// Step 4: capture-then-verify. Every cert in the bundle must be
	// anchored in the handshake peer chain. This guards against a MITM
	// returning an unrelated bundle, and against the subtler attack of
	// appending an attacker CA to an otherwise genuine bundle.
	if err := verifyBundleMatchesPeerChain(bundleCerts, peerChain); err != nil {
		return "", err
	}

	o.cpCAPool = pool
	return string(body), nil
}

// parseCAPEMBundle decodes a PEM-encoded sequence of X.509 certificates.
// Returns ErrCABundleInvalid when no valid cert block is found.
func parseCAPEMBundle(pemBytes []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	var certs []*x509.Certificate
	rest := pemBytes
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, ErrCABundleInvalid{Reason: err.Error()}
		}
		pool.AddCert(cert)
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, ErrCABundleInvalid{Reason: "no valid certificate blocks found"}
	}
	return pool, certs, nil
}

// verifyBundleMatchesPeerChain checks that EVERY cert in bundleCerts is
// anchored in the TLS handshake peer chain: it either shares a
// SubjectPublicKeyInfo with a peer-chain cert, or it signed one of the
// peer-chain certs (the root case — servers commonly omit the
// self-signed root from the handshake). Requiring every cert to match
// prevents a MITM from smuggling an attacker CA into an otherwise
// genuine bundle; "at least one matches" would let the rest of the pool
// be poisoned. Returns ErrCABundleVerifyFailed on the first unanchored
// cert.
//
// Note this strict policy intentionally rejects rotation-style bundles
// carrying CAs unrelated to the live handshake chain — at greenfield
// bootstrap time the CP was just installed, so its bundle is exactly
// its fresh chain.
func verifyBundleMatchesPeerChain(bundleCerts, peerChain []*x509.Certificate) error {
	if len(peerChain) == 0 {
		return ErrCABundleVerifyFailed{Reason: "TLS handshake returned an empty peer chain"}
	}
	spkiHash := func(c *x509.Certificate) ([32]byte, error) {
		der, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			return [32]byte{}, err
		}
		return sha256.Sum256(der), nil
	}
	peerPins := make(map[[32]byte]struct{}, len(peerChain))
	for _, c := range peerChain {
		pin, err := spkiHash(c)
		if err != nil {
			continue
		}
		peerPins[pin] = struct{}{}
	}
	for _, c := range bundleCerts {
		pin, err := spkiHash(c)
		if err != nil {
			return ErrCABundleVerifyFailed{Reason: fmt.Sprintf(
				"marshal SPKI for bundle cert %q: %v", c.Subject.CommonName, err)}
		}
		if _, ok := peerPins[pin]; ok {
			continue
		}
		// Root case: accept when this bundle cert signed a cert that
		// was presented in the handshake.
		signedPeer := false
		for _, p := range peerChain {
			if p.CheckSignatureFrom(c) == nil {
				signedPeer = true
				break
			}
		}
		if !signedPeer {
			return ErrCABundleVerifyFailed{Reason: fmt.Sprintf(
				"bundle cert %q is not anchored in the TLS handshake chain", c.Subject.CommonName)}
		}
	}
	return nil
}

// ControlPlaneCAPool returns the CP CA pool, fetching it on first call
// via fetchControlPlaneCABundle and caching the result. Subsequent
// calls return the cached pool without a network round-trip.
func (o *Orchestrator) ControlPlaneCAPool(ctx context.Context) (*x509.CertPool, error) {
	if o.cpCAPool != nil {
		return o.cpCAPool, nil
	}
	if _, err := o.fetchControlPlaneCABundle(ctx); err != nil {
		return nil, err
	}
	return o.cpCAPool, nil
}

// fetchControlPlaneSPKIPin captures the base64-encoded SHA-256 of the
// SubjectPublicKeyInfo from the control plane's webservice TLS leaf
// cert. The pin is staged alongside the CA bundle at
// /config/mac/<mac>/bootstrap-spki-pin so the new node's autoinstall
// can persist it for the platform's BootstrapTrust SPKI strategy when
// the bundle delivery path is unavailable (e.g., misconfigured pxeboot
// HTTP, or operator booted from external media).
//
// SPKI pinning is one of go-truststrap's three supported strategies
// (DANE / Noise / SPKI / Auto). Unlike DANE, SPKI requires no DNS
// infrastructure — the pin is shipped out-of-band via the orchestrator's
// per-MAC config endpoint. Unlike embedded, the pin is only ~64 bytes
// vs the full bundle, making it cheap to refresh after CA rotation.
//
// Uses tls.Dial directly with InsecureSkipVerify (we are establishing
// the trust anchor — there is by definition no anchor to verify
// against yet). Same security perimeter argument as
// fetchControlPlaneCABundle.
func (o *Orchestrator) fetchControlPlaneSPKIPin(ctx context.Context) (string, error) {
	// Guard: cpCAPool must be populated by fetchControlPlaneCABundle first
	// so we can verify the peer chain against a known-good anchor.
	if o.cpCAPool == nil {
		return "", ErrCABundleRequired{}
	}

	var cpNode *DiscoveredNode
	for i := range o.discovered {
		if o.discovered[i].Role == RoleControlPlane {
			cpNode = &o.discovered[i]
			break
		}
	}
	if cpNode == nil {
		return "", fmt.Errorf("no control-plane node discovered")
	}

	cpIPs := staticIPsFromOverrides(cpNode.Overrides)
	if len(cpIPs) == 0 {
		return "", fmt.Errorf("control-plane node has no static IP override")
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", cpIPs[0]+":"+cpWebservicePort, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // bootstrap trust anchor capture
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", fmt.Errorf("control plane TLS handshake returned empty peer chain")
	}

	// Verify the captured chain against the CA pool established by
	// fetchControlPlaneCABundle before extracting any pin from it. This
	// is the verification half of the custom-verifier pattern: the
	// handshake skipped library verification, so the pin is only ever
	// derived from a chain the verified bundle actually issued.
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         o.cpCAPool,
		Intermediates: intermediates,
	}); err != nil {
		return "", ErrCABundleVerifyFailed{Reason: fmt.Sprintf(
			"control plane TLS chain does not verify against the captured CA bundle: %v", err)}
	}

	// The trust anchor for ACME enrollment is the CA cert that signed
	// the CP webservice cert. Use the issuer (last in chain) when the
	// chain is presented in standard leaf→root order; fall back to the
	// leaf when the BMC sent only the leaf (some Supermicro firmware).
	var anchor *x509.Certificate
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		if c.IsCA {
			anchor = c
			break
		}
	}
	if anchor == nil {
		anchor = chain[0]
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(anchor.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI: %w", err)
	}
	sum := sha256.Sum256(spkiDER)
	// go-truststrap accepts base64-std encoded pins (matches the format
	// `--bootstrap-spki-pin` consumes in iso create).
	pin := base64.StdEncoding.EncodeToString(sum[:])

	o.logger.Info("bootstrap: captured CP SPKI pin",
		slog.String("anchor_cn", anchor.Subject.CommonName),
		slog.Bool("anchor_is_ca", anchor.IsCA),
		slog.String("pin_sha256_b64", pin))

	return pin, nil
}
