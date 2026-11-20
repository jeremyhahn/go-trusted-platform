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

package backends

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// LUKS backend typed errors.

// ErrLUKSVolumeNotFound indicates the requested device is not a LUKS2 volume.
var ErrLUKSVolumeNotFound = errors.New("luks backend: device is not a LUKS2 volume")

// ErrLUKSFIDO2NotWired indicates FIDO2 enrollment has not been wired to a
// live authenticator backend. Implementations must set the FIDO2 handler via
// SetFIDO2Handler before EnrollFIDO2 is called.
var ErrLUKSFIDO2NotWired = errors.New("luks backend: fido2 handler not configured")

// ErrLUKSTPMNotWired indicates TPM enrollment is not yet wired. TPM sealing
// is a separate story (see docs/architecture/groovy-fluttering-cloud Phase 2).
var ErrLUKSTPMNotWired = errors.New("luks backend: tpm handler not configured")

// ErrLUKSHardwareUnavailable indicates the default handler factory ran but
// the underlying hardware (TPM device, FIDO2 authenticator) could not be
// reached. EnrollFIDO2 and EnrollTPM return this so callers can distinguish
// "no handler configured" (ErrLUKSFIDO2NotWired / ErrLUKSTPMNotWired) from
// "handler configured but hardware unavailable".
var ErrLUKSHardwareUnavailable = errors.New("luks backend: hardware unavailable")

// ErrLUKSNewSlotNotFound indicates AddKey returned success but no keyslot
// appeared that was absent before the call. The backend reports no slot rather
// than guess one: the highest existing slot is not the new one when the free
// slots are not contiguous.
var ErrLUKSNewSlotNotFound = errors.New("luks backend: no new keyslot appeared after adding the key")

// ErrLUKSTestUnlockUnverified is returned by TestUnlock: the request carries
// no credential, so the backend cannot derive the keyslot's key and verify
// the master key, and it never reports success from slot metadata alone.
var ErrLUKSTestUnlockUnverified = errors.New("luks backend: test unlock cannot verify a keyslot without its credential")

// ErrLUKSTokenMissing indicates an enrollment handler returned no token for
// the new keyslot. A FIDO2 or TPM keyslot without its token cannot be used by
// any unlock strategy.
var ErrLUKSTokenMissing = errors.New("luks backend: the handler returned no token for the new keyslot")

// ErrLUKSRotationKDFNotApproved indicates ChangePassphrase refused to rotate
// a keyslot whose KDF the FIPS keyslot policy does not approve: go-luks2
// keeps the slot's KDF on rotation, so it would write another such slot.
// The wrapped fips error names the KDF.
var ErrLUKSRotationKDFNotApproved = errors.New("luks backend: passphrase rotation refused: the keyslot KDF is not FIPS-approved")

// LUKSTokenWriteError reports that the token binding a newly added keyslot to
// its unlock method could not be written — for example because the header's
// JSON area is full (luks2.ErrMetadataTooLarge) or no token slot is free.
// The keyslot was removed again; when RollbackErr is set that removal failed
// too and the keyslot is still on the volume, without a token.
type LUKSTokenWriteError struct {
	Slot        int
	Err         error
	RollbackErr error
}

// Error implements the error interface.
func (e *LUKSTokenWriteError) Error() string {
	msg := "luks backend: writing the token for keyslot " + strconv.Itoa(e.Slot) + " failed: " + e.Err.Error()
	if e.RollbackErr != nil {
		return msg + "; removing the keyslot also failed and it is still on the volume: " + e.RollbackErr.Error()
	}
	return msg + "; the keyslot was removed"
}

// Unwrap returns the token write cause and, when set, the rollback cause.
func (e *LUKSTokenWriteError) Unwrap() []error {
	if e.RollbackErr != nil {
		return []error{e.Err, e.RollbackErr}
	}
	return []error{e.Err}
}

// LUKSFIDO2Handler is the narrow surface LUKSBackend needs from the FIDO2
// layer to enroll a volume keyslot. It's decoupled from the full FIDO2
// backend so the LUKS backend can be constructed with just the pieces it
// needs.
//
// EnrollCredential performs a CTAP2 MakeCredential with hmac-secret and
// returns the derived key bytes that will be used as the volume passphrase.
type LUKSFIDO2Handler interface {
	EnrollCredential(ctx context.Context, credentialID string, requirePIN, requireUV bool) ([]byte, error)
}

// LUKSFIDO2EnrollingHandler is an optional richer contract — when the
// configured LUKSFIDO2Handler also implements this interface, LUKSBackend
// calls DeriveEnroll so it can capture the HMAC-SECRET salt and persist it
// alongside the credential id in the LUKS2 token. Handlers that only
// implement the minimum EnrollCredential interface get the simpler
// credential-only token.
type LUKSFIDO2EnrollingHandler interface {
	LUKSFIDO2Handler
	DeriveEnroll(ctx context.Context, credentialID string, requirePIN, requireUV bool) (*LUKSFIDO2EnrollResult, error)
}

// LUKSTPMHandler is the narrow surface LUKSBackend needs to seal a volume
// key to TPM PCR state. It returns the derived passphrase used for the
// keyslot and the token blob that must be written to the LUKS2 header.
type LUKSTPMHandler interface {
	Seal(ctx context.Context, handle string, pcrs []int32) (passphrase []byte, tokenJSON []byte, err error)
}

// LUKSBackend implements daemon.LUKSBackend over go-luks2. All mutating ops
// delegate to package-level luks2 helpers. go-luks2 requires root for real
// device operations, so the LUKS *service* performs the root check before
// invoking the backend.
type LUKSBackend struct {
	logger *logging.Logger
	fido2  LUKSFIDO2Handler
	tpm    LUKSTPMHandler

	// tpmOpener is the platform's selected TPM the default TPM handler
	// seals over (WithLUKSTPMOpener). nil keeps the SDK default device.
	tpmOpener TPMOpener

	// kdfCost, when set, fixes the KDF cost of every keyslot the backend
	// writes. Production leaves it nil so go-luks2 calibrates the cost for
	// the host; the package's unit tests set it so a keyslot write does not
	// spend seconds in the KDF.
	kdfCost *luksKDFCost

	// locks serializes keyslot and token mutations per volume. go-luks2
	// takes its header lock for one call only and releases it after each
	// AddKey or ImportToken, so the backend's snapshot, add, detect-new-slot,
	// token-write and rollback sequence is not atomic on its own: two
	// concurrent enrollments could detect the same new slot, bind a token to
	// the other's slot, or roll back the other's credential. Every mutating
	// method holds, for its whole sequence, the volume's mutex and an
	// exclusive flock on <luksLockDir>/<sha256 of the resolved path>.lock
	// (lockDevice), so separate backends and processes (platformd and each
	// embedded platformctl host build their own) serialize too. The device
	// node itself is not flocked: go-luks2 takes its own LOCK_NB flock there
	// per call, which a held lock would make fail. locksMu guards the map.
	locksMu sync.Mutex
	locks   map[string]chan struct{}

	// fido2Sem (capacity 1) serializes every call into the shared FIDO2
	// handler. The go-xkms handler reads, overwrites and restores its
	// config timeout without synchronization, and one handler serves every
	// request, so two enrollments (even on different devices) must not call
	// it at once. A waiter whose context ends gives up with ctx.Err()
	// (acquireFIDO2) instead of queueing behind a ceremony that may wait on
	// a user touch. The slot is released when the handler call returns; a
	// call that returns early on a cancelled context may leave its SDK call
	// running, so the SDK-backed handler (luksFIDO2Handler) also holds its
	// own lock from inside the goroutine running that call until the call
	// returns.
	fido2Sem chan struct{}

	// fipsActive reports whether the platform FIPS keyslot policy applies.
	// nil means luksFIPSActive; the package's tests set it as a seam.
	fipsActive func() bool
}

// fipsPolicyActive reports whether the platform FIPS keyslot policy applies
// to this backend's keyslot writes.
func (b *LUKSBackend) fipsPolicyActive() bool {
	if b.fipsActive != nil {
		return b.fipsActive()
	}
	return luksFIPSActive()
}

// luksVolumeKey returns the key that selects a volume's mutation lock.
// Aliases such as a /dev/disk/by-uuid link and the kernel name resolve to
// the same node, so they share one mutex. When the path cannot be resolved
// the cleaned text is used; the later go-luks2 call reports the bad path.
func luksVolumeKey(device string) string {
	resolved, err := filepath.EvalSymlinks(device)
	if err != nil {
		return filepath.Clean(device)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return filepath.Clean(device)
	}
	return abs
}

// luksDefaultLockDir holds one lock file per LUKS volume, shared by every
// backend and process on the host.
const luksDefaultLockDir = "/run/platform/luks-locks"

// luksLockDir is the per-volume lock directory; the package's tests point it
// at a temporary directory.
var luksLockDir = luksDefaultLockDir

// luksVolumeLockPath returns the lock file of device: the hex SHA-256 of its
// resolved path, so every alias of one volume shares one lock file.
func luksVolumeLockPath(device string) string {
	sum := sha256.Sum256([]byte(luksVolumeKey(device)))
	return filepath.Join(luksLockDir, hex.EncodeToString(sum[:])+".lock")
}

// lockDevice takes the volume's in-process lock (a one-slot channel keyed by
// its resolved path, created on first use), then an exclusive flock on the
// volume's lock file, and returns the unlock that releases both. Both waits
// end when ctx does: lockDevice then returns ctx.Err(), and it also returns
// ctx.Err(), holding nothing, when ctx ended while the lock was being taken,
// so a caller whose request is gone never starts its disk mutation. It fails
// closed: when the flock cannot be taken it releases the in-process lock and
// returns an error, and the caller mutates nothing. The lock file stays in place after unlock, since
// removing it would race with another locker.
func (b *LUKSBackend) lockDevice(ctx context.Context, device string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := luksVolumeKey(device)
	b.locksMu.Lock()
	if b.locks == nil {
		b.locks = make(map[string]chan struct{})
	}
	sem, ok := b.locks[key]
	if !ok {
		sem = make(chan struct{}, 1)
		b.locks[key] = sem
	}
	b.locksMu.Unlock()
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-sem }

	path := luksVolumeLockPath(device)
	if err := os.MkdirAll(luksLockDir, 0o700); err != nil {
		release()
		return nil, fmt.Errorf("luks: volume lock directory %s: %w", luksLockDir, err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		release()
		return nil, fmt.Errorf("luks: open volume lock %s: %w", path, err)
	}
	if err := flockContext(ctx, f); err != nil {
		_ = f.Close()
		release()
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("luks: lock volume %s: %w", key, err)
	}
	unlock := func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		release()
	}
	// The context may have ended while the lock was being taken: the caller
	// mutates nothing then.
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// acquireFIDO2 takes the shared FIDO2 handler's slot (fido2Sem), or returns
// ctx.Err() when ctx ends first. The returned release frees the slot once.
func (b *LUKSBackend) acquireFIDO2(ctx context.Context) (func(), error) {
	select {
	case b.fido2Sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() { once.Do(func() { <-b.fido2Sem }) }, nil
}

// luksFlockRetry is how often a contended volume flock is retried while the
// caller's context is live.
const luksFlockRetry = 20 * time.Millisecond

// flockContext takes an exclusive flock on f, retrying a contended
// non-blocking attempt until it succeeds or ctx ends (then ctx.Err()).
func flockContext(ctx context.Context, f *os.File) error {
	var ticker *time.Ticker
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			if ticker != nil {
				ticker.Stop()
			}
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case !errors.Is(err, unix.EWOULDBLOCK):
			if ticker != nil {
				ticker.Stop()
			}
			return err
		}
		if ticker == nil {
			ticker = time.NewTicker(luksFlockRetry)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		}
	}
}

// luksKDFCost is a fixed keyslot KDF cost (see LUKSBackend.kdfCost): the
// KDF, hash and PBKDF2 iteration time of an added keyslot, and the Argon2
// cost of a recovery keyslot, whose options carry no PBKDF2 iteration time.
type luksKDFCost struct {
	kdfType        string
	hash           string
	pbkdfIterTime  int
	argon2Time     int
	argon2Memory   int
	argon2Parallel int
}

// applyAddKey fixes the KDF of a new keyslot's options. A nil cost leaves
// the options as the FIPS policy resolved them.
func (c *luksKDFCost) applyAddKey(opts *luks2.AddKeyOptions) {
	if c == nil {
		return
	}
	opts.KDFType = c.kdfType
	opts.Hash = c.hash
	opts.PBKDFIterTime = c.pbkdfIterTime
}

// applyRecovery fixes the Argon2 cost of a recovery keyslot's options. A
// nil cost leaves the options as the FIPS policy resolved them.
func (c *luksKDFCost) applyRecovery(opts *luks2.RecoveryKeyOptions) {
	if c == nil {
		return
	}
	opts.Argon2Time = c.argon2Time
	opts.Argon2Memory = c.argon2Memory
	opts.Argon2Parallel = c.argon2Parallel
}

// Compile-time assertion.
var _ daemon.LUKSBackend = (*LUKSBackend)(nil)

// LUKSBackendOption configures optional dependencies on NewLUKSBackend.
type LUKSBackendOption func(*LUKSBackend)

// WithLUKSFIDO2Handler pre-injects a FIDO2 handler at construction time.
// Equivalent to calling SetFIDO2Handler after construction; exposed as an
// option so serve.go can build the backend and its handler in one place.
func WithLUKSFIDO2Handler(h LUKSFIDO2Handler) LUKSBackendOption {
	return func(b *LUKSBackend) { b.fido2 = h }
}

// WithLUKSTPMHandler pre-injects a TPM handler at construction time.
func WithLUKSTPMHandler(h LUKSTPMHandler) LUKSBackendOption {
	return func(b *LUKSBackend) { b.tpm = h }
}

// WithLUKSTPMOpener sets the TPM the default TPM handler seals over (the
// platform's selected TPM). Pass it before WithDefaultLUKSHandlers; nil
// keeps the SDK default device.
func WithLUKSTPMOpener(o TPMOpener) LUKSBackendOption {
	return func(b *LUKSBackend) { b.tpmOpener = o }
}

// WithDefaultLUKSHandlers attempts to build default FIDO2 and TPM handlers
// from the host environment. Failures are non-fatal — when a handler can't
// be constructed the backend is left unwired and the corresponding Enroll
// method returns ErrLUKSHardwareUnavailable instead of panicking.
func WithDefaultLUKSHandlers() LUKSBackendOption {
	return func(b *LUKSBackend) {
		if b.fido2 == nil {
			if h, err := newDefaultLUKSFIDO2Handler(b.logger); err == nil {
				b.fido2 = h
			} else if b.logger != nil {
				b.logger.Debug("default luks fido2 handler unavailable", "err", err.Error())
			}
		}
		if b.tpm == nil {
			if h, err := defaultLUKSTPMHandler(b.logger, b.tpmOpener); err == nil {
				b.tpm = h
			} else if b.logger != nil {
				b.logger.Debug("default luks tpm handler unavailable", "err", err.Error())
			}
		}
	}
}

// NewLUKSBackend constructs a new LUKS backend. Options can pre-inject FIDO2
// and TPM handlers or opt into default-handler construction from the host.
func NewLUKSBackend(logger *logging.Logger, opts ...LUKSBackendOption) *LUKSBackend {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	b := &LUKSBackend{logger: logger, fido2Sem: make(chan struct{}, 1)}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// SetFIDO2Handler injects a FIDO2 enrollment handler. Passing nil disables
// FIDO2 enrollment.
func (b *LUKSBackend) SetFIDO2Handler(h LUKSFIDO2Handler) {
	b.fido2 = h
}

// SetTPMHandler injects a TPM sealing handler. Passing nil disables TPM
// enrollment.
func (b *LUKSBackend) SetTPMHandler(h LUKSTPMHandler) {
	b.tpm = h
}

// TPMHandler returns the TPM sealing handler, or nil when TPM enrollment
// is not wired.
func (b *LUKSBackend) TPMHandler() LUKSTPMHandler {
	return b.tpm
}

// luksKeySlotTypeMap routes LUKS2 token/keyslot types onto the service-layer
// LUKSKeyType enum. Entries cover both raw keyslot.Type values and token
// type discriminators that imply the slot purpose.
var luksKeySlotTypeMap = map[string]daemon.LUKSKeyType{
	"luks2":                  daemon.LUKSKeyTypePassphrase,
	"passphrase":             daemon.LUKSKeyTypePassphrase,
	"fido2":                  daemon.LUKSKeyTypeFIDO2,
	"fido2-manual":           daemon.LUKSKeyTypeFIDO2,
	"systemd-fido2":          daemon.LUKSKeyTypeFIDO2,
	"tpm":                    daemon.LUKSKeyTypeTPM,
	"tpm2":                   daemon.LUKSKeyTypeTPM,
	"systemd-tpm2":           daemon.LUKSKeyTypeTPM,
	"recovery":               daemon.LUKSKeyTypeRecovery,
	"systemd-recovery":       daemon.LUKSKeyTypeRecovery,
	"trusted-platform-luks2": daemon.LUKSKeyTypePassphrase,
}

// Status returns high-level volume state.
func (b *LUKSBackend) Status(ctx context.Context, device string) (*daemon.LUKSStatus, error) {
	info, err := luks2.GetVolumeInfo(device)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, ErrLUKSVolumeNotFound
	}
	active := make([]int32, 0, len(info.ActiveKeyslots))
	for _, s := range info.ActiveKeyslots {
		active = append(active, int32(s))
	}
	return &daemon.LUKSStatus{
		Device:      device,
		IsLUKS:      true,
		Version:     int32(info.Version),
		UUID:        info.UUID,
		Label:       info.Label,
		Cipher:      info.Cipher,
		ActiveSlots: active,
	}, nil
}

// ListSlots enumerates active keyslots and labels each with its backing key
// type inferred from the LUKS2 tokens.
func (b *LUKSBackend) ListSlots(ctx context.Context, device string) (*daemon.LUKSListSlotsResult, error) {
	slots, err := luks2.ListKeyslots(device)
	if err != nil {
		return nil, err
	}
	slotTypes := resolveSlotTypes(device)

	out := make([]daemon.LUKSKeyslot, 0, len(slots))
	for _, s := range slots {
		kt := daemon.LUKSKeyTypePassphrase
		if typ, ok := luksKeySlotTypeMap[s.Type]; ok {
			kt = typ
		}
		// Token-derived type wins when present — it captures FIDO2 / TPM
		// slots whose underlying keyslot.Type is still "luks2".
		if tkt, ok := slotTypes[s.ID]; ok {
			kt = tkt
		}
		out = append(out, daemon.LUKSKeyslot{
			Slot:     int32(s.ID),
			Type:     kt,
			KeySize:  int32(s.KeySize),
			Priority: int32(s.Priority),
		})
	}
	return &daemon.LUKSListSlotsResult{Device: device, Slots: out}, nil
}

// Info returns full volume metadata including the LUKS2 JSON header.
func (b *LUKSBackend) Info(ctx context.Context, device string) (*daemon.LUKSInfo, error) {
	info, err := luks2.GetVolumeInfo(device)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, ErrLUKSVolumeNotFound
	}
	list, err := b.ListSlots(ctx, device)
	if err != nil {
		return nil, err
	}
	// Serialise the metadata as JSON for callers that want the raw header.
	var metaJSON []byte
	if info.Metadata != nil {
		metaJSON, _ = json.Marshal(info.Metadata)
	}
	sectorSize := luks2.DefaultSectorSize
	if info.SectorSize != 0 {
		sectorSize = info.SectorSize
	}
	return &daemon.LUKSInfo{
		Device:       device,
		UUID:         info.UUID,
		Label:        info.Label,
		Version:      int32(info.Version),
		Cipher:       info.Cipher,
		KeySize:      volumeKeyBits(info, list.Slots),
		SectorSize:   int32(sectorSize),
		Slots:        list.Slots,
		MetadataJSON: string(metaJSON),
	}, nil
}

// volumeKeyBits returns the volume key size in bits. go-luks2's
// GetVolumeInfo does not fill VolumeInfo.KeySize, so the size falls back to
// the keyslots: every LUKS2 keyslot stores the volume key, and a keyslot's
// key_size is in bytes. Zero means the volume has no keyslot to read it from.
func volumeKeyBits(info *luks2.VolumeInfo, slots []daemon.LUKSKeyslot) int32 {
	if info.KeySize != 0 {
		return int32(info.KeySize)
	}
	for _, s := range slots {
		if s.KeySize > 0 {
			return s.KeySize * 8
		}
	}
	return 0
}

// EnrollPassphrase adds a new passphrase keyslot.
func (b *LUKSBackend) EnrollPassphrase(ctx context.Context, req *daemon.LUKSEnrollPassphraseRequest) (*daemon.LUKSEnrollPassphraseResult, error) {
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return nil, err
	}
	defer unlock()

	before, err := luks2.ListKeyslots(req.Device)
	if err != nil {
		return nil, err
	}
	addOpts, err := fipsAddKeyOptions()
	if err != nil {
		return nil, err
	}
	b.kdfCost.applyAddKey(addOpts)
	if err := luks2.AddKey(
		req.Device,
		[]byte(req.ExistingPassphrase),
		[]byte(req.NewPassphrase),
		addOpts,
	); err != nil {
		return nil, err
	}
	newSlot, err := detectNewSlot(req.Device, before)
	if err != nil {
		return nil, err
	}
	return &daemon.LUKSEnrollPassphraseResult{Slot: int32(newSlot)}, nil
}

// EnrollFIDO2 derives a passphrase from a FIDO2 credential and adds a new
// keyslot backed by it. The caller must have attached a FIDO2 handler via
// SetFIDO2Handler before calling. When the handler implements the richer
// LUKSFIDO2EnrollingHandler interface the HMAC-SECRET salt is captured and
// persisted in the LUKS2 token so the slot can be unlocked later without
// any server-side state. A request with RequirePIN is refused with
// ErrLUKSFIDO2PINUnsupported before anything is derived or written.
func (b *LUKSBackend) EnrollFIDO2(ctx context.Context, req *daemon.LUKSEnrollFIDO2Request) (*daemon.LUKSEnrollFIDO2Result, error) {
	// Refused before any derivation or keyslot write (see
	// ErrLUKSFIDO2PINUnsupported).
	if req.RequirePIN {
		return nil, ErrLUKSFIDO2PINUnsupported
	}
	if b.fido2 == nil {
		return nil, ErrLUKSFIDO2NotWired
	}

	var (
		key       []byte
		tokenJSON []byte
		err       error
	)
	if rich, ok := b.fido2.(LUKSFIDO2EnrollingHandler); ok {
		release, aerr := b.acquireFIDO2(ctx)
		if aerr != nil {
			return nil, aerr
		}
		res, derr := rich.DeriveEnroll(ctx, req.CredentialID, req.RequirePIN, req.RequireUV)
		release()
		if derr != nil {
			return nil, derr
		}
		key = res.DerivedKey
		tokenJSON = res.TokenJSON
	} else {
		release, aerr := b.acquireFIDO2(ctx)
		if aerr != nil {
			return nil, aerr
		}
		key, err = b.fido2.EnrollCredential(ctx, req.CredentialID, req.RequirePIN, req.RequireUV)
		release()
		if err != nil {
			return nil, err
		}
	}
	defer clearBytes(key)

	// The FIDO2 derivation (a touch) stays outside the device lock.
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return nil, err
	}
	defer unlock()

	before, err := luks2.ListKeyslots(req.Device)
	if err != nil {
		return nil, err
	}
	addOpts, err := fipsAddKeyOptions()
	if err != nil {
		return nil, err
	}
	b.kdfCost.applyAddKey(addOpts)
	if err := luks2.AddKey(
		req.Device,
		[]byte(req.ExistingPassphrase),
		key,
		addOpts,
	); err != nil {
		return nil, err
	}
	newSlot, err := detectNewSlot(req.Device, before)
	if err != nil {
		return nil, err
	}

	// A rich handler's token carries its salt and is written as-is; a minimal
	// LUKSFIDO2Handler gets a fido2-manual token built here.
	fallback := &luks2.Token{
		Type:            "fido2-manual",
		FIDO2Credential: req.CredentialID,
		FIDO2UPRequired: req.RequireUV,
	}
	tokenID, err := writeEnrollToken(req.Device, newSlot, tokenJSON, fallback)
	if err != nil {
		return nil, err
	}

	return &daemon.LUKSEnrollFIDO2Result{
		Slot:    int32(newSlot),
		TokenID: strconv.Itoa(tokenID),
	}, nil
}

// EnrollTPM seals a volume key to TPM PCR state and adds the resulting
// keyslot + token.
func (b *LUKSBackend) EnrollTPM(ctx context.Context, req *daemon.LUKSEnrollTPMRequest) (*daemon.LUKSEnrollTPMResult, error) {
	if b.tpm == nil {
		return nil, ErrLUKSTPMNotWired
	}
	passphrase, tokenJSON, err := b.tpm.Seal(ctx, req.Handle, req.PCRs)
	if err != nil {
		return nil, err
	}
	defer clearBytes(passphrase)

	// The TPM seal stays outside the device lock.
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return nil, err
	}
	defer unlock()

	before, err := luks2.ListKeyslots(req.Device)
	if err != nil {
		return nil, err
	}
	addOpts, err := fipsAddKeyOptions()
	if err != nil {
		return nil, err
	}
	b.kdfCost.applyAddKey(addOpts)
	if err := luks2.AddKey(
		req.Device,
		[]byte(req.ExistingPassphrase),
		passphrase,
		addOpts,
	); err != nil {
		return nil, err
	}
	newSlot, err := detectNewSlot(req.Device, before)
	if err != nil {
		return nil, err
	}

	tokenID, err := writeEnrollToken(req.Device, newSlot, tokenJSON, nil)
	if err != nil {
		return nil, err
	}
	return &daemon.LUKSEnrollTPMResult{
		Slot:    int32(newSlot),
		TokenID: strconv.Itoa(tokenID),
	}, nil
}

// EnrollRecovery generates a random recovery key, adds it to the volume, and
// returns it so the caller can present it to the operator.
func (b *LUKSBackend) EnrollRecovery(ctx context.Context, req *daemon.LUKSEnrollRecoveryRequest) (*daemon.LUKSEnrollRecoveryResult, error) {
	recoveryOpts := &luks2.RecoveryKeyOptions{Format: luks2.RecoveryKeyFormatDashed}
	if err := fipsRecoveryKeyPolicy(&recoveryOpts.KDFType); err != nil {
		return nil, err
	}
	b.kdfCost.applyRecovery(recoveryOpts)
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return nil, err
	}
	defer unlock()
	recoveryKey, err := luks2.AddRecoveryKey(
		req.Device,
		[]byte(req.ExistingPassphrase),
		recoveryOpts,
	)
	if err != nil {
		return nil, err
	}
	defer recoveryKey.Clear()

	// Presenting the key to the operator is the whole purpose of enrolling
	// one, and the result crosses the API as a string, so this is the point
	// of display that FormattedString documents. The protected copy is still
	// wiped by the deferred Clear.
	formatted, err := recoveryKey.FormattedString()
	if err != nil {
		return nil, err
	}

	return &daemon.LUKSEnrollRecoveryResult{
		Slot:        int32(recoveryKey.Keyslot),
		RecoveryKey: formatted,
	}, nil
}

// RemoveKey kills a keyslot. The slot index must be an existing, active slot.
func (b *LUKSBackend) RemoveKey(ctx context.Context, req *daemon.LUKSRemoveKeyRequest) error {
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return err
	}
	defer unlock()
	return luks2.KillKeyslot(req.Device, int(req.Slot))
}

// TestUnlock does not report a successful unlock it cannot prove. The
// request carries no credential, so the backend can neither derive the
// keyslot's key (a passphrase, a FIDO2 assertion or a TPM unseal) nor verify
// the master key against the volume digest; a keyslot that is listed in the
// header may still be corrupt or its credential unavailable. It therefore
// never returns true: a device that is not a LUKS2 volume returns its read
// error, and every other request returns false with
// ErrLUKSTestUnlockUnverified until credential verification is available.
func (b *LUKSBackend) TestUnlock(ctx context.Context, req *daemon.LUKSTestUnlockRequest) (bool, error) {
	if _, err := luks2.ListKeyslots(req.Device); err != nil {
		return false, err
	}
	return false, ErrLUKSTestUnlockUnverified
}

// ChangePassphrase rotates the secret on an existing passphrase slot.
func (b *LUKSBackend) ChangePassphrase(ctx context.Context, req *daemon.LUKSChangePassphraseRequest) error {
	unlock, err := b.lockDevice(ctx, req.Device)
	if err != nil {
		return err
	}
	defer unlock()
	if b.fipsPolicyActive() {
		// go-luks2 ChangeKey keeps the slot's KDF, so rotating a slot whose
		// KDF the FIPS policy refuses would write another such slot.
		slots, err := luks2.ListKeyslots(req.Device)
		if err != nil {
			return err
		}
		for _, s := range slots {
			if s.ID != int(req.Slot) {
				continue
			}
			if err := fips.ValidateKDFForMode(s.KDFType, true); err != nil {
				return fmt.Errorf("%w: keyslot %d: %w", ErrLUKSRotationKDFNotApproved, req.Slot, err)
			}
			break
		}
		_, metadata, err := luks2.ReadHeader(req.Device)
		if err != nil {
			return err
		}
		if slot := metadata.Keyslots[strconv.Itoa(int(req.Slot))]; slot != nil && slot.KDF != nil && slot.KDF.Hash != "" {
			if err := fips.ValidateHashForMode(slot.KDF.Hash, true); err != nil {
				return fmt.Errorf("%w: keyslot %d: %w", ErrLUKSRotationKDFNotApproved, req.Slot, err)
			}
		}
	}
	return luks2.ChangeKey(
		req.Device,
		[]byte(req.OldPassphrase),
		[]byte(req.NewPassphrase),
		int(req.Slot),
	)
}

// detectNewSlot returns the slot number that appears in the current slot list
// but was absent in the prior snapshot, or ErrLUKSNewSlotNotFound.
func detectNewSlot(device string, before []luks2.KeyslotInfo) (int, error) {
	after, err := luks2.ListKeyslots(device)
	if err != nil {
		return 0, err
	}
	priors := make(map[int]struct{}, len(before))
	for _, s := range before {
		priors[s.ID] = struct{}{}
	}
	for _, s := range after {
		if _, ok := priors[s.ID]; !ok {
			return s.ID, nil
		}
	}
	return 0, ErrLUKSNewSlotNotFound
}

// writeEnrollToken writes the LUKS2 token that binds the freshly added
// keyslot slot to its unlock method and returns the token ID. A keyslot
// without its token is unusable, so on any failure the keyslot is removed
// again and a *LUKSTokenWriteError is returned.
func writeEnrollToken(device string, slot int, tokenJSON []byte, fallback *luks2.Token) (int, error) {
	tokenID, err := importEnrollToken(device, slot, tokenJSON, fallback)
	if err != nil {
		return 0, &LUKSTokenWriteError{
			Slot:        slot,
			Err:         err,
			RollbackErr: luks2.KillKeyslot(device, slot),
		}
	}
	return tokenID, nil
}

// importEnrollToken writes tokenJSON, with its keyslots rewritten to name
// slot, into the first free token slot. Without tokenJSON it writes fallback
// instead; with neither it returns ErrLUKSTokenMissing.
func importEnrollToken(device string, slot int, tokenJSON []byte, fallback *luks2.Token) (int, error) {
	if len(tokenJSON) == 0 && fallback == nil {
		return 0, ErrLUKSTokenMissing
	}
	tokenID, err := luks2.FindFreeTokenSlot(device)
	if err != nil {
		return 0, err
	}
	keyslot := strconv.Itoa(slot)
	if len(tokenJSON) > 0 {
		patched, err := injectKeyslotsIntoTokenJSON(tokenJSON, keyslot)
		if err != nil {
			return 0, err
		}
		if err := luks2.ImportTokenJSON(device, tokenID, patched); err != nil {
			return 0, err
		}
		return tokenID, nil
	}
	fallback.Keyslots = []string{keyslot}
	if err := luks2.ImportToken(device, tokenID, fallback); err != nil {
		return 0, err
	}
	return tokenID, nil
}

// resolveSlotTypes inspects the LUKS2 token table to derive slot types beyond
// what ListKeyslots reports. Errors reading tokens are non-fatal — the caller
// simply gets passphrase as the default.
func resolveSlotTypes(device string) map[int]daemon.LUKSKeyType {
	types := map[int]daemon.LUKSKeyType{}
	tokens, err := luks2.ListTokens(device)
	if err != nil {
		return types
	}
	for _, tok := range tokens {
		kt, ok := luksKeySlotTypeMap[tok.Type]
		if !ok {
			continue
		}
		for _, sid := range tok.Keyslots {
			n, convErr := strconv.Atoi(sid)
			if convErr != nil {
				continue
			}
			types[n] = kt
		}
	}
	return types
}

// injectKeyslotsIntoTokenJSON parses a token JSON blob and sets the
// "keyslots" field to [slot]. This keeps the handler ignorant of the slot
// number while letting the backend preserve the handler-authored token
// schema (credential id, salt, sealed blobs, etc.).
func injectKeyslotsIntoTokenJSON(tokenJSON []byte, slot string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(tokenJSON, &raw); err != nil {
		return nil, err
	}
	raw["keyslots"] = []string{slot}
	return json.Marshal(raw)
}

// clearBytes zeroes a byte slice. Lifted verbatim from go-luks2's internal
// helper to avoid re-exporting or depending on the private symbol.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DefaultRootChecker returns a RootChecker that checks the effective UID.
// Injected into the LUKS service from the daemon startup path.
func DefaultRootChecker() daemon.RootChecker {
	return daemon.RootCheckerFunc(func() bool { return os.Geteuid() == 0 })
}

// newDefaultLUKSFIDO2Handler opens the default FIDO2 handler; tests replace
// it to wire a handler without an authenticator attached.
var newDefaultLUKSFIDO2Handler = defaultLUKSFIDO2Handler

// defaultLUKSFIDO2Handler builds a production FIDO2 handler using the
// package-default go-xkms configuration and HID enumerator. Returns
// ErrLUKSHardwareUnavailable if no authenticator library can be initialised.
func defaultLUKSFIDO2Handler(logger *logging.Logger) (LUKSFIDO2EnrollingHandler, error) {
	defaultCfg := fido2.DefaultConfig
	xkmsHandler, err := fido2.NewHandler(&defaultCfg, fido2.NewDefaultEnumerator())
	if err != nil {
		return nil, errors.Join(ErrLUKSHardwareUnavailable, err)
	}
	return NewLUKSFIDO2Handler(logger, xkmsHandler, defaultCfg.RelyingPartyID)
}

// defaultLUKSTPMHandler builds a production TPM handler over opener, the
// platform's selected TPM; a nil opener falls back to the SDK default device
// (DefaultTPMOpener). Callers inspect the returned error to decide whether
// to wire the handler or leave it unset.
func defaultLUKSTPMHandler(logger *logging.Logger, opener TPMOpener) (LUKSTPMHandler, error) {
	if opener == nil {
		opener = DefaultTPMOpener()
	}
	h, err := NewLUKSTPMHandler(logger, opener)
	if err != nil {
		return nil, errors.Join(ErrLUKSHardwareUnavailable, err)
	}
	return h, nil
}
