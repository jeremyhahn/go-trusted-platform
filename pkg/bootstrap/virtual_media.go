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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

const (
	// defaultInstallLogTimeout caps how long we wait for a node's
	// install.log to appear at the bootstrap container's forensic
	// sink. ISO-based installs on spinning rust can legitimately run
	// 20+ minutes because of the image write + package unpack + first
	// boot. 45 minutes is comfortable headroom; if the log never
	// appears after that, something is genuinely stuck and human
	// intervention is warranted.
	defaultInstallLogTimeout = 45 * time.Minute

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
	powerVerifyRetries = 5

	// powerVerifyInterval is the delay between consecutive PowerStatus
	// polls during post-command verification.
	powerVerifyInterval = 3 * time.Second

	// registrationFetchTimeout caps how long we wait for a single
	// registration.json fetch from the bootstrap server. This is a
	// best-effort probe so a short timeout avoids blocking the health
	// candidate list on a slow or unreachable deployer.
	registrationFetchTimeout = 5 * time.Second
)

// virtualMediaShareName is the SMB share name exposed by the bootstrap
// container's smbd (see build/docker/bootstrap/smb.conf [boot] stanza).
// The container bind-mounts the deployer-host data dir as /data and exports
// it via this share name.
const virtualMediaShareName = "boot"

// NodeRegistration is the JSON payload that platformd uploads to the
// bootstrap server at /installs/<hostname>/registration.json after it
// starts on a freshly-installed node. The IP field is the address
// platformd is actually listening on — which may differ from the DHCP
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
//  6. Wait for the node's health endpoint via the existing waitForHealth.
//  7. Best-effort UnmountVirtualMedia after success -- log on failure but
//     don't fail the phase.
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

	// 2. Build the BMC client. Reuse the same factory + config builder
	//    Phase 0 uses for MAC discovery so per-node BMC settings (protocol,
	//    skip-tls-verify, encryption key) propagate consistently.
	bmcConfig := buildBMCConfig(&node.NodeConfig)
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
	}

	// 4. Set boot device to CD/DVD, one-shot only. After install we want
	//    the node to boot from disk on subsequent power cycles.
	if err := client.SetBootDevice(ctx, bmc.BootDeviceCDROM, false); err != nil {
		o.bestEffortUnmount(ctx, client, node.Hostname)
		return ErrBootDeviceSetFailed{
			Hostname: node.Hostname,
			Device:   string(bmc.BootDeviceCDROM),
			Cause:    err,
		}
	}

	// 5. Power-cycle. Use PowerReset if the node is on, PowerOn if off.
	//
	// Record the install-attempt timestamp BEFORE triggering the power
	// cycle so the install-log poller can reject any stale log
	// uploaded by a prior run. The freshness gate prevents the
	// orchestrator from reporting instant success based on a previously-
	// successful install.log still sitting in the bootstrap container's
	// forensic sink (witnessed 2026-04-08: 12ms "success" on a brand-
	// new install attempt because a 4-hour-old log was still there).
	installStart := time.Now()
	state, err := client.PowerStatus(ctx)
	if err != nil {
		o.bestEffortUnmount(ctx, client, node.Hostname)
		return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "status", Cause: err}
	}
	if state == bmc.PowerStateOff {
		if err := client.PowerOn(ctx); err != nil {
			o.bestEffortUnmount(ctx, client, node.Hostname)
			return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "on", Cause: err}
		}
	} else {
		if err := client.PowerReset(ctx); err != nil {
			o.bestEffortUnmount(ctx, client, node.Hostname)
			return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "reset", Cause: err}
		}
	}
	o.logger.Info("bootstrap: virtual-media: power cycle issued, verifying state transition",
		slog.String("hostname", node.Hostname))

	// 5a. Verify the server actually transitioned to PowerStateOn.
	//     Supermicro X10 BMCs sometimes acknowledge PowerOn over IPMI
	//     but leave the chassis off. Close the current IPMI session
	//     (it may be stale after the virtual media operations) and
	//     open a fresh client for the verification polls.
	if closeErr := client.Close(); closeErr != nil {
		o.logger.Warn("bootstrap: virtual-media: pre-verify BMC client close failed",
			slog.String("hostname", node.Hostname),
			slog.String("error", closeErr.Error()))
	}
	verifyClient, verifyErr := o.bmcFactory.NewClient(bmcConfig)
	if verifyErr != nil {
		o.bestEffortUnmount(ctx, client, node.Hostname)
		return ErrPowerControlFailed{
			Hostname:  node.Hostname,
			Operation: "verify-reconnect",
			Cause:     verifyErr,
		}
	}
	defer func() {
		if closeErr := verifyClient.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: verify BMC client close failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", closeErr.Error()))
		}
	}()

	verified := false
	var lastState bmc.PowerState
	ticker := time.NewTicker(powerVerifyInterval)
	defer ticker.Stop()
	for attempt := 0; attempt < powerVerifyRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ErrPowerControlFailed{
				Hostname:  node.Hostname,
				Operation: "verify",
				Cause:     ctx.Err(),
			}
		case <-ticker.C:
		}
		lastState, err = verifyClient.PowerStatus(ctx)
		if err != nil {
			o.logger.Warn("bootstrap: virtual-media: power verify poll failed",
				slog.String("hostname", node.Hostname),
				slog.Int("attempt", attempt+1),
				slog.String("error", err.Error()))
			continue
		}
		if lastState == bmc.PowerStateOn {
			verified = true
			o.logger.Info("bootstrap: virtual-media: power state verified on",
				slog.String("hostname", node.Hostname),
				slog.Int("attempt", attempt+1))
			break
		}
		o.logger.Warn("bootstrap: virtual-media: power state not yet on",
			slog.String("hostname", node.Hostname),
			slog.Int("attempt", attempt+1),
			slog.String("state", string(lastState)))
	}
	if !verified {
		o.bestEffortUnmount(ctx, verifyClient, node.Hostname)
		return ErrPowerStateVerificationFailed{
			Hostname: node.Hostname,
			Expected: string(bmc.PowerStateOn),
			Actual:   string(lastState),
			Retries:  powerVerifyRetries,
		}
	}

	// 6. Wait for the installer to finish. The old flow tried to wait
	//    for the installed platformd to bind its health endpoint, but
	//    that's fundamentally racy on virtual-media installs because:
	//
	//      a. The installer runs in the Alpine live environment, not
	//         the installed OS. Its only communication channel back
	//         to the orchestrator is the forensic install-log PUT
	//         endpoint (pkg/iso/customize.go upload_install_log).
	//      b. Many installers end with `poweroff` (the default
	//         alpine-install convention), so after install success
	//         the node sits at power-off state until someone powers
	//         it back on. A health check against the node's hostname
	//         during that window hangs until timeout and reports
	//         failure when the install actually succeeded.
	//      c. `node.Hostname` is almost never DNS-resolvable during
	//         bootstrap -- there's no DNS yet -- so the health checker
	//         ends up stuck in TCP retries even in the happy case.
	//
	//    Instead we poll the bootstrap container's /installs/{hostname}/
	//    endpoint which autoinstall.sh populates on BOTH success and
	//    failure paths. The platform_hostname kernel cmdline baked
	//    into the ISO at build time (pkg/iso/customize.go
	//    buildHostnameParam) keys the upload path to the node config,
	//    so the orchestrator and installer agree on where the log
	//    lives without any DNS in the picture.
	installURL, urlErr := installLogBaseURL(&o.config.Deployer)
	if urlErr != nil {
		o.bestEffortUnmount(ctx, verifyClient, node.Hostname)
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: urlErr}
	}
	poller := &InstallLogPoller{
		BaseURL:  installURL,
		Hostname: sanitizeHostnameForInstallPath(node.Hostname),
		Since:    installStart,
		Interval: defaultInstallLogPollInterval,
		Logger:   o.logger,
	}
	installCtx, installCancel := context.WithTimeout(ctx, defaultInstallLogTimeout)
	defer installCancel()
	logResult, installErr := poller.Wait(installCtx)
	if installErr != nil && (logResult == nil || !logResult.Found) {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    fmt.Errorf("install log never appeared at %s/installs/%s/install.log: %w", installURL, node.Hostname, installErr),
		}
	}
	if !logResult.Success() {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    fmt.Errorf("installer exited with code %d; see install.log at %s/installs/%s/install.log", logResult.ExitCode, installURL, node.Hostname),
		}
	}
	o.logger.Info("bootstrap: virtual-media: installer reported success",
		slog.String("hostname", node.Hostname),
		slog.Int("exit_code", logResult.ExitCode),
		slog.Int("log_bytes", len(logResult.Raw)))

	// 7. The BMC client we opened in step 2 has been idle for the
	//    entire install wait -- potentially 20+ minutes. Supermicro
	//    ATEN BMCs time out RMCP+ sessions in the low-minute range
	//    and any subsequent command returns "UDP receive failed:
	//    i/o timeout". Close the stale verify client and open a fresh
	//    one for all post-install ops (unmount, boot device, power).
	if closeErr := verifyClient.Close(); closeErr != nil {
		o.logger.Warn("bootstrap: virtual-media: stale BMC client close failed",
			slog.String("hostname", node.Hostname),
			slog.String("error", closeErr.Error()))
	}
	client, err = o.bmcFactory.NewClient(bmcConfig)
	if err != nil {
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: fmt.Errorf("reopen BMC client for post-install ops: %w", err)}
	}
	// Note: the deferred Close registered in step 2 still holds a
	// reference to the ORIGINAL client (now closed). Register a new
	// cleanup for the fresh one so it also gets closed at function
	// return. The old deferred Close is harmless -- calling Close on
	// an already-closed client is a no-op.
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: fresh BMC client close failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", closeErr.Error()))
		}
	}()

	// 8. Unmount the virtual CD BEFORE cycling into the installed OS so
	//    the BIOS doesn't try to re-boot into the installer on the next
	//    reset. This was the "endless install loop" the operator hit
	//    before the unmount was wired into this path.
	o.logger.Info("bootstrap: virtual-media: unmounting virtual CD",
		slog.String("hostname", node.Hostname))
	o.bestEffortUnmount(ctx, client, node.Hostname)
	o.logger.Info("bootstrap: virtual-media: unmount step completed",
		slog.String("hostname", node.Hostname))

	// 9. Switch to persistent disk boot. The installer writes a fresh
	//    UEFI boot entry pointing at the UKI, but legacy-BIOS and
	//    NVRAM-wipe scenarios still need the BMC to assert disk as the
	//    next boot device so the POST handoff lands on the newly
	//    installed bootloader instead of falling through to PXE.
	if err := client.SetBootDevice(ctx, bmc.BootDeviceDisk, true); err != nil {
		return ErrBootDeviceSetFailed{
			Hostname: node.Hostname,
			Device:   string(bmc.BootDeviceDisk),
			Cause:    err,
		}
	}

	// 10. Power the host back on if the installer left it in S5. Alpine
	//     autoinstall calls `poweroff` at the end by default; detect
	//     that state via BMC and wake it up.
	postState, err := client.PowerStatus(ctx)
	if err != nil {
		return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "status", Cause: err}
	}
	switch postState {
	case bmc.PowerStateOff:
		o.logger.Info("bootstrap: virtual-media: host at S5 after install, powering on for first-boot",
			slog.String("hostname", node.Hostname))
		if err := client.PowerOn(ctx); err != nil {
			return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "on", Cause: err}
		}
	case bmc.PowerStateOn:
		// Installer may have rebooted itself; still cycle once to ensure
		// the host is running from the newly-written disk rather than a
		// stale post-install state lingering from the Alpine live env.
		o.logger.Info("bootstrap: virtual-media: host still on after install, resetting for first-boot",
			slog.String("hostname", node.Hostname))
		if err := client.PowerReset(ctx); err != nil {
			return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "reset", Cause: err}
		}
	default:
		o.logger.Warn("bootstrap: virtual-media: unknown power state after install",
			slog.String("hostname", node.Hostname),
			slog.String("state", string(postState)))
	}

	// 10a. Verify the host actually reached PowerStateOn. The Supermicro
	//      X10 ATEN BMC sometimes ACKs a PowerOn IPMI command but the
	//      chassis never transitions -- close the stale session and poll
	//      with a fresh client.
	o.logger.Info("bootstrap: virtual-media: verifying post-install power state",
		slog.String("hostname", node.Hostname))
	if closeErr := client.Close(); closeErr != nil {
		o.logger.Warn("bootstrap: virtual-media: post-install BMC client close failed",
			slog.String("hostname", node.Hostname),
			slog.String("error", closeErr.Error()))
	}
	postVerifyClient, postVerifyErr := o.bmcFactory.NewClient(bmcConfig)
	if postVerifyErr != nil {
		return ErrVirtualMediaBootFailed{Hostname: node.Hostname, Cause: fmt.Errorf("reopen BMC for post-install power verify: %w", postVerifyErr)}
	}
	defer func() {
		if closeErr := postVerifyClient.Close(); closeErr != nil {
			o.logger.Warn("bootstrap: virtual-media: post-verify BMC client close failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", closeErr.Error()))
		}
	}()
	postVerifyTicker := time.NewTicker(powerVerifyInterval)
	defer postVerifyTicker.Stop()
	postVerified := false
	for attempt := 1; attempt <= powerVerifyRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ErrPowerControlFailed{Hostname: node.Hostname, Operation: "post-install-verify", Cause: ctx.Err()}
		case <-postVerifyTicker.C:
		}
		st, stErr := postVerifyClient.PowerStatus(ctx)
		if stErr != nil {
			o.logger.Warn("bootstrap: virtual-media: post-install power status check failed",
				slog.String("hostname", node.Hostname),
				slog.Int("attempt", attempt),
				slog.String("error", stErr.Error()))
			continue
		}
		if st == bmc.PowerStateOn {
			o.logger.Info("bootstrap: virtual-media: post-install power state verified on",
				slog.String("hostname", node.Hostname),
				slog.Int("attempt", attempt))
			postVerified = true
			break
		}
		o.logger.Warn("bootstrap: virtual-media: post-install power state not yet on, retrying",
			slog.String("hostname", node.Hostname),
			slog.Int("attempt", attempt),
			slog.String("state", string(st)))
		// Retry power on if still off
		if st == bmc.PowerStateOff {
			_ = postVerifyClient.PowerOn(ctx)
		}
	}
	if !postVerified {
		return ErrPowerStateVerificationFailed{
			Hostname: node.Hostname,
			Expected: string(bmc.PowerStateOn),
			Actual:   string(bmc.PowerStateOff),
			Retries:  powerVerifyRetries,
		}
	}
	// Use postVerifyClient for health check since client was closed
	client = postVerifyClient

	// 11. Wait for the newly-installed platformd to bind its health
	//     endpoint. Now that the host has been rebooted once from disk
	//     with the freshly-written UKI, the normal health waiter is
	//     meaningful. Try the node's hostname (if DNS is available) and
	//     any addresses the installer embedded in the forensic manifest.
	//     The registration.json uploaded by platformd after first-boot
	//     carries the real post-DHCP IP, so it's checked first.
	healthAddrs := candidateHealthAddresses(node, logResult, installURL)
	if len(healthAddrs) == 0 {
		o.logger.Warn("bootstrap: virtual-media: no usable health addresses after install, skipping health wait",
			slog.String("hostname", node.Hostname))
		return nil
	}
	healthCtx, healthCancel := context.WithTimeout(ctx, defaultPostInstallHealthTimeout)
	defer healthCancel()
	if healthErr := o.waitForHealthAny(healthCtx, healthAddrs, installURL, node.Hostname); healthErr != nil {
		return ErrVirtualMediaBootFailed{
			Hostname: node.Hostname,
			Cause:    ErrHealthCheckFailed{Address: strings.Join(healthAddrs, ","), Cause: healthErr},
		}
	}
	return nil
}

// waitForHealthAny polls every candidate address until ONE of them
// returns a healthy response or the context expires. On each tick it
// also re-reads registration.json from the bootstrap server so it
// picks up the node's actual post-DHCP IP as soon as platformd
// uploads it (which happens after the first-boot networking is up).
func (o *Orchestrator) waitForHealthAny(ctx context.Context, addresses []string, registrationBaseURL string, hostname string) error {
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
		// Re-read registration.json on each tick to pick up new IP
		if registrationBaseURL != "" && hostname != "" {
			if regIP, fetchErr := fetchRegistrationIP(registrationBaseURL, hostname); fetchErr == nil {
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
	// with its actual post-DHCP address. Best-effort: if the fetch fails
	// we fall through to the existing heuristic candidates.
	if registrationBaseURL != "" {
		if regIP, fetchErr := fetchRegistrationIP(registrationBaseURL, node.Hostname); fetchErr == nil {
			add(regIP)
		}
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
// bootstrap server and returns the IP field. The URL is constructed as
// <baseURL>/installs/<sanitized-hostname>/registration.json. Returns a
// typed ErrRegistrationFetch on any failure (HTTP error, non-200 status,
// JSON decode error, or empty IP field).
func fetchRegistrationIP(baseURL, hostname string) (string, error) {
	sanitized := sanitizeHostnameForInstallPath(hostname)
	regURL := baseURL + "/installs/" + sanitized + "/registration.json"

	client := &http.Client{Timeout: registrationFetchTimeout}
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
