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

package bmc

import (
	"context"
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// DefaultRotationInterval is the default cadence for scheduled BMC
// password rotation. Matches the ACME 90-day cert rotation cadence so
// credential and certificate lifetimes are correlated and predictable.
const DefaultRotationInterval = 90 * 24 * time.Hour

// DefaultPasswordLength is the default generated password length in
// bytes. 20 bytes is the IPMI 2.0 maximum for the long-form Set User
// Password command; using the full width maximizes entropy.
const DefaultPasswordLength = 20

// passwordAlphabet is the character set used by GenerateRandomPassword.
// Restricted to URL-safe alphanumerics because several BMC firmware
// revisions reject non-alphanumeric characters in passwords (undocumented).
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// PasswordGenerator produces fresh password material for rotation. It
// is called once per rotation attempt. Implementations must return
// cryptographically random bytes held in locked memory.
type PasswordGenerator func() (*memguard.MemoryEnclave, error)

// UserManagerFactory opens a UserManager session bound to a specific
// set of credentials. Rotation needs two independent sessions in a
// single operation (verify with new password, optional rollback with
// new password) so the factory pattern is required; constructing a
// UserManager from (Config, Credentials) lets the engine inject each
// set of credentials in turn without mutating the caller's Config.
type UserManagerFactory func(ctx context.Context, cfg *Config, creds *Credentials) (ManagedUserManager, error)

// RotationEngine orchestrates the store-ahead-apply-verify-rollback
// sequence for BMC password rotation. It is stateless beyond its
// dependencies — each RotateOnce call is self-contained.
//
// Safe for concurrent use across different BMC names. Concurrent
// rotation of the same BMC is undefined — callers should serialize
// rotations per BMC via the secret store's distributed lock or a
// per-name mutex at the service layer.
type RotationEngine struct {
	store    CredentialStore
	factory  UserManagerFactory
	generate PasswordGenerator
	logger   *slog.Logger
}

// RotationOptions configures a RotationEngine.
type RotationOptions struct {
	// Store is the credential store that will hold the rotated
	// credentials. Required.
	Store CredentialStore

	// Factory opens UserManager sessions bound to explicit
	// credentials. Required.
	Factory UserManagerFactory

	// Generate produces the new password on each rotation. Defaults
	// to GenerateRandomPassword with DefaultPasswordLength bytes.
	Generate PasswordGenerator

	// Logger receives structured rotation events. May be nil.
	Logger *slog.Logger
}

// NewRotationEngine constructs a RotationEngine from opts. Returns
// ErrInvalidRotationConfig if Store or Factory is nil.
func NewRotationEngine(opts RotationOptions) (*RotationEngine, error) {
	if opts.Store == nil {
		return nil, ErrInvalidRotationConfig{Field: "Store", Reason: "required"}
	}
	if opts.Factory == nil {
		return nil, ErrInvalidRotationConfig{Field: "Factory", Reason: "required"}
	}
	gen := opts.Generate
	if gen == nil {
		gen = func() (*memguard.MemoryEnclave, error) {
			return GenerateRandomPassword(DefaultPasswordLength)
		}
	}
	return &RotationEngine{
		store:    opts.Store,
		factory:  opts.Factory,
		generate: gen,
		logger:   opts.Logger,
	}, nil
}

// RotateOnce performs a single password rotation for the BMC
// identified by name. cfg is the connection config for the BMC; slot
// is the IPMI user slot (or Redfish account ID) whose password should
// be rotated.
//
// Sequence:
//
//  1. Fetch current credentials (oldCreds) from the store.
//  2. Generate a fresh password P_new.
//  3. Store P_new to the store FIRST — if anything below fails, the
//     store reflects the best guess of what's actually on the BMC.
//  4. Open a session with oldCreds and issue SetUserPassword(slot, P_new).
//  5. Close the old session.
//  6. Open a new session with P_new; invoke a harmless read (MaxUsers)
//     to verify the new password authenticates successfully.
//  7. If verify succeeds: close new session, return nil.
//  8. If verify fails: attempt rollback by re-authenticating with
//     P_new (which IS what the BMC has) and setting it back to the
//     old password. On rollback success, write oldCreds back to the
//     store and return ErrRotationReverted. On rollback failure,
//     leave the store pointing at P_new (which matches BMC state)
//     and return ErrRotationCatastrophic — operator intervention
//     required.
func (e *RotationEngine) RotateOnce(ctx context.Context, name string, cfg *Config, slot uint8) error {
	if name == "" {
		return ErrInvalidCredentials{Reason: "empty name"}
	}
	if cfg == nil {
		return ErrNilConfig{}
	}

	// Step 1: fetch current credentials.
	oldCreds, err := e.store.Get(ctx, name)
	if err != nil {
		return err
	}
	// oldCreds is owned by the store; we must not destroy it here.

	// Step 2: generate new password.
	newPwd, err := e.generate()
	if err != nil {
		return ErrRotationGenerate{Cause: err}
	}
	newCreds := &Credentials{Username: oldCreds.Username, Password: newPwd}

	// Step 3: store-ahead. Persist new creds before touching the BMC
	// so the store reflects the best-guess actual state even if the
	// BMC update fails mid-flight.
	if err := e.store.Put(ctx, name, newCreds); err != nil {
		newCreds.Destroy()
		return ErrRotationStoreAhead{Cause: err}
	}
	// newCreds is now owned by the store.

	e.log("rotation: new password stored, applying to BMC", "name", name, "slot", slot)

	// Step 4: apply new password via a session authenticated with
	// oldCreds.
	applyErr := e.applyPassword(ctx, cfg, oldCreds, slot, newCreds)

	// Step 5+6: verify with a fresh session using newCreds.
	if applyErr == nil {
		if err := e.verifyPassword(ctx, cfg, newCreds); err == nil {
			e.log("rotation: verified", "name", name, "slot", slot)
			return nil
		} else {
			applyErr = err
		}
	}

	// Step 8: failure path. Attempt rollback.
	e.log("rotation: apply or verify failed, attempting rollback",
		"name", name, "slot", slot, "cause", applyErr.Error())

	if rbErr := e.rollback(ctx, cfg, newCreds, slot, oldCreds); rbErr != nil {
		e.log("rotation: CATASTROPHIC — rollback failed; store holds new password matching BMC",
			"name", name, "slot", slot,
			"apply_err", applyErr.Error(), "rollback_err", rbErr.Error())
		return ErrRotationCatastrophic{
			Name:      name,
			ApplyErr:  applyErr,
			RollbackE: rbErr,
		}
	}

	// Rollback succeeded: BMC has oldCreds again, store must also.
	restored := oldCreds.Clone()
	if err := e.store.Put(ctx, name, restored); err != nil {
		restored.Destroy()
		// BMC has old password, but store has new. Unusual state.
		return ErrRotationStoreRollback{Cause: err}
	}
	return ErrRotationReverted{Cause: applyErr}
}

// applyPassword issues Set User Password on the BMC using a session
// authenticated with oldCreds.
func (e *RotationEngine) applyPassword(ctx context.Context, cfg *Config, oldCreds *Credentials, slot uint8, newCreds *Credentials) error {
	mgr, err := e.factory(ctx, cfg, oldCreds)
	if err != nil {
		return ErrRotationConnect{Phase: "apply", Cause: err}
	}
	defer mgr.Close()
	if err := mgr.SetUserPassword(ctx, slot, newCreds.Password); err != nil {
		return ErrRotationApply{Cause: err}
	}
	return nil
}

// verifyPassword authenticates against the BMC with the new password
// and issues a cheap read to confirm it is accepted.
func (e *RotationEngine) verifyPassword(ctx context.Context, cfg *Config, newCreds *Credentials) error {
	mgr, err := e.factory(ctx, cfg, newCreds)
	if err != nil {
		return ErrRotationConnect{Phase: "verify", Cause: err}
	}
	defer mgr.Close()
	if _, err := mgr.MaxUsers(ctx); err != nil {
		return ErrRotationVerify{Cause: err}
	}
	return nil
}

// rollback authenticates with the new password (which IS on the BMC
// post-apply) and sets the password back to the old value.
func (e *RotationEngine) rollback(ctx context.Context, cfg *Config, newCreds *Credentials, slot uint8, oldCreds *Credentials) error {
	mgr, err := e.factory(ctx, cfg, newCreds)
	if err != nil {
		return ErrRotationConnect{Phase: "rollback", Cause: err}
	}
	defer mgr.Close()
	return mgr.SetUserPassword(ctx, slot, oldCreds.Password)
}

// log emits a structured log entry if a logger is configured.
func (e *RotationEngine) log(msg string, args ...any) {
	if e.logger != nil {
		e.logger.Info("bmc: "+msg, args...)
	}
}

// GenerateRandomPassword returns n cryptographically random bytes
// drawn from an alphanumeric alphabet, held in a locked memguard
// buffer.
//
// The alphabet restriction guards against firmware that rejects
// special characters in passwords (observed on several X10 ATEN
// revisions). Length is capped at 20 bytes to match the IPMI 2.0
// long-form Set User Password limit.
func GenerateRandomPassword(n int) (*memguard.MemoryEnclave, error) {
	if n <= 0 {
		return nil, ErrInvalidRotationConfig{Field: "length", Reason: "must be positive"}
	}
	if n > 20 {
		n = 20
	}
	// Read 2x the required entropy; reject-sample to uniform alphabet.
	out := make([]byte, n)
	alphaLen := byte(len(passwordAlphabet))
	// 256 mod alphaLen → rejection threshold for unbiased sampling.
	// len(passwordAlphabet) = 62, floor(256/62)*62 = 4*62 = 248.
	const ceiling = byte(248)
	buf := make([]byte, 0, n*2)
	written := 0
	for written < n {
		if len(buf) == 0 {
			buf = make([]byte, n*2)
			if _, err := rand.Read(buf); err != nil {
				zero(out)
				zero(buf)
				return nil, ErrRotationGenerate{Cause: err}
			}
		}
		b := buf[0]
		buf = buf[1:]
		if b >= ceiling {
			continue
		}
		out[written] = passwordAlphabet[b%alphaLen]
		written++
	}
	// out is copied into the locked buffer and zeroed by memguard.New.
	return memguard.NewMemoryEnclave(out), nil
}
