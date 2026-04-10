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
	"errors"
	"fmt"
	"os"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// Package app / firstboot_handoff.go implements the platformd side of the
// firstboot handoff protocol. The protocol is designed to deliver exactly
// one secret (the LUKS recovery passphrase) from platform-initrd to the
// first-run platformd process WITHOUT that secret ever touching persistent
// storage outside of the root LUKS volume itself.
//
// Wire path:
//
//	pkg/firstboot/strategy.go       applyRecoveryKeyStrategy(escrow)
//	    writes plaintext recovery passphrase to
//	    /run/platform/firstboot-handoff/recovery.key  (tmpfs, 0600, root only)
//	        |
//	        |  switch_root into production rootfs
//	        V
//	pkg/app/firstboot_handoff.go    (*App).ConsumeFirstbootHandoff()
//	    reads /run/platform/firstboot-handoff/recovery.key
//	    stores it at tenants/{tenant}/nodes/{node}/secrets/luks/recovery
//	    shreds + unlinks the tmpfs file
//	    records a non-secret audit breadcrumb at
//	        tenants/{tenant}/nodes/{node}/params/firstboot/escrowed_at
//
// Because the tmpfs directory does not survive a reboot, the handoff is
// inherently single-consumer: if platformd crashes before consumption, the
// passphrase is lost and the operator must unlock using the TPM-sealed slot
// or reprovision. This is acceptable because the operator explicitly opted
// into the escrow strategy and the TPM slot is always the primary unlock
// path.

// Handoff paths — must match pkg/firstboot/strategy.go.
const (
	firstbootHandoffDir         = "/run/platform/firstboot-handoff"
	firstbootHandoffRecoveryKey = firstbootHandoffDir + "/recovery.key"
)

// FirstbootHandoffResult summarizes what the consumer did. The fields are
// safe to log — none of them contain the recovery passphrase itself.
type FirstbootHandoffResult struct {
	// Present is true when a handoff file was found and consumed.
	Present bool
	// Strategy names the disposition applied. Currently only "escrow"
	// ever reaches this consumer; "destroy" never stages a handoff.
	Strategy string
	// SecretPath is the tenant-keyspace path under which the recovery
	// passphrase was stored in the secret store.
	SecretPath string
	// ParamPath is the tenant-keyspace path under which the audit
	// breadcrumb was stored.
	ParamPath string
	// EscrowedAt is the timestamp at which escrow completed.
	EscrowedAt time.Time
}

// ConsumeFirstbootHandoff looks for a staged firstboot handoff file and, if
// present, stores its contents in the tenant secret store and shreds the
// tmpfs copy. It is a no-op on every boot after the first because the tmpfs
// directory does not persist across reboots.
//
// Errors are returned to the caller but are generally non-fatal at the
// daemon startup level — an operator can always recover manually from the
// TPM-sealed LUKS slot. Callers SHOULD log the error loudly so the operator
// notices but SHOULD NOT abort platformd startup on it.
func (app *App) ConsumeFirstbootHandoff(ctx context.Context) (*FirstbootHandoffResult, error) {
	result := &FirstbootHandoffResult{}

	// Fast path: file does not exist → nothing to do.
	data, err := os.ReadFile(firstbootHandoffRecoveryKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, fmt.Errorf("read firstboot handoff: %w", err)
	}
	result.Present = true
	result.Strategy = "escrow"

	// Defer the shred+unlink so the secret leaves tmpfs even if the
	// store-to-secrets path below fails.
	defer func() {
		if shredErr := shredAndUnlink(firstbootHandoffRecoveryKey, len(data)); shredErr != nil {
			app.Logger.Warnf("firstboot-handoff: failed to shred %s: %v",
				firstbootHandoffRecoveryKey, shredErr)
		}
		// Best-effort: remove the now-empty handoff directory so its
		// presence on future boots is a loud signal of a retry attempt
		// rather than an orphaned empty dir.
		_ = os.Remove(firstbootHandoffDir)
		// Zero the in-memory copy.
		for i := range data {
			data[i] = 0
		}
	}()

	// Resolve target paths from the tenant keyspace.
	nodeID := app.Hostname
	if nodeID == "" {
		return result, fmt.Errorf("firstboot-handoff: cannot determine node id (app.Hostname is empty)")
	}
	tenantID := app.TenantID
	if tenantID == "" {
		// Should not happen after Init — Init defaults to "platform" —
		// but belt-and-braces because losing the handoff silently is
		// worse than rejecting a malformed identity.
		return result, fmt.Errorf("firstboot-handoff: cannot determine tenant id (app.TenantID is empty)")
	}

	secretPath, err := tenant.NodeSecret(tenantID, nodeID, tenant.NodeSecretLUKSRecovery)
	if err != nil {
		return result, fmt.Errorf("firstboot-handoff: build secret path: %w", err)
	}
	result.SecretPath = secretPath

	paramPath, err := tenant.NodeParam(tenantID, nodeID, tenant.NodeParamFirstbootEscrowedAt)
	if err != nil {
		return result, fmt.Errorf("firstboot-handoff: build param path: %w", err)
	}
	result.ParamPath = paramPath

	// Resolve the secrets service. platformd may legitimately run without
	// a secret store configured (e.g., test or embedded modes) — in that
	// case we log and bail, but still shred the tmpfs file so the secret
	// doesn't linger.
	secretsSvc := app.Secrets()
	if secretsSvc == nil {
		return result, fmt.Errorf(
			"firstboot-handoff: SecretsService not available; recovery passphrase has been shredded from %s and is now unrecoverable except via TPM-sealed LUKS slot",
			firstbootHandoffRecoveryKey)
	}

	client := NewSecretsServiceClient(secretsSvc, app.Logger.Slog())

	escrowedAt := time.Now().UTC()
	metadata := map[string]string{
		"source":       "firstboot-handoff",
		"strategy":     "escrow",
		"node_id":      nodeID,
		"tenant_id":    tenantID,
		"escrowed_at":  escrowedAt.Format(time.RFC3339),
		"content_type": "text/plain",
	}

	if err := client.StoreSecret(ctx, secretPath, data, metadata); err != nil {
		return result, fmt.Errorf("firstboot-handoff: store secret at %s: %w", secretPath, err)
	}

	// Record the audit breadcrumb at the param path. This one is not a
	// secret — it exists purely so the future Node view can surface "this
	// node has an escrowed recovery passphrase available" without having
	// to query the secret store ACL path.
	breadcrumb := []byte(escrowedAt.Format(time.RFC3339))
	breadcrumbMeta := map[string]string{
		"source":   "firstboot-handoff",
		"category": "param",
	}
	if err := client.StoreSecret(ctx, paramPath, breadcrumb, breadcrumbMeta); err != nil {
		// Non-fatal: the secret itself landed, the breadcrumb is just
		// a convenience surface.
		app.Logger.Warnf("firstboot-handoff: store breadcrumb at %s: %v", paramPath, err)
	}

	result.EscrowedAt = escrowedAt
	app.Logger.Info("firstboot-handoff: recovery passphrase escrowed",
		"tenant", tenantID,
		"node", nodeID,
		"secret_path", secretPath,
	)
	return result, nil
}

// shredAndUnlink overwrites a file with zeros before removing it. It is a
// best-effort scrub on top of tmpfs — the kernel will eventually reclaim
// the underlying page, but the zero-write removes the obvious plaintext
// pattern from the filesystem cache in the meantime.
func shredAndUnlink(path string, size int) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	zero := make([]byte, size)
	if _, err := f.Write(zero); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// Compile-time check that baasservice.SecretsService still exposes the
// signature NewSecretsServiceClient expects. If the upstream SDK renames
// the interface, this line fails to build instead of the handoff consumer
// silently going out of service.
var _ baasservice.SecretsService = baasservice.SecretsService(nil)
