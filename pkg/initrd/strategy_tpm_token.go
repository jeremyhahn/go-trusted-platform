package initrd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/google/go-tpm/tpm2/transport"
	xkmsluks "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/luks"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// StrategyNameTPMToken names the strategy that unseals the systemd-tpm2
// LUKS2 header token written by TPM enrolment (ruling 673).
const StrategyNameTPMToken = "TPM2-Token"

// tpmTokenType is the LUKS2 token type TPM enrolment writes.
const tpmTokenType = "systemd-tpm2"

// ErrTPMTokenUnsealerUnavailable is returned when no TPM unsealer could be
// opened for the systemd-tpm2 token.
var ErrTPMTokenUnsealerUnavailable = errors.New("initrd: no TPM unsealer for the systemd-tpm2 token")

// TokenUnsealer unseals the passphrase a systemd-tpm2 token carries. The
// default is the go-xkms TPM sealer; SetUnsealer replaces it (tests, or a
// caller holding its own TPM session).
type TokenUnsealer interface {
	Unseal(ctx context.Context, token *luks.Token) ([]byte, error)
}

// TPMTokenStrategy unlocks a volume through the keyslot a systemd-tpm2
// header token names, unsealing the token's blob with the TPM. It is the
// boot side of the SDK TPM enrolment wired in WireSDKBackends.
type TPMTokenStrategy struct {
	platform *Platform
	logger   *logging.Logger
	unsealer TokenUnsealer
	priority int
	// sealPending reports that the firstboot seal is not yet confirmed
	// (installer.luks still on the ESP). Only a TPM-PCR unlock confirms it
	// (shouldConfirmSeal, pkg/boot/commands/sealconfirm.go), so the token
	// strategy stands aside until then.
	sealPending func() bool
	// upgradeSealsPending reports that the insecure upgrade seals are still
	// on the ESP. They are deleted only by a TPM-PCR unlock
	// (deleteInsecureUpgradeSeals, strategy_tpm_pcr.go), so the token
	// strategy stands aside while they exist (#1692).
	upgradeSealsPending func() bool
	// extendPCR restores the runtime platform-PCR state that enrolment
	// sealed against, before any token is unsealed.
	extendPCR func(ctx context.Context) error
}

// NewTPMTokenStrategy returns the strategy with the default TPM unsealer.
func NewTPMTokenStrategy(platform *Platform, logger *logging.Logger) *TPMTokenStrategy {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	// Unseal over the platform's selected TPM, the device enrolment sealed
	// on; without one, the SDK default device.
	opener := xkmsluks.DefaultTPMOpener()
	if platform != nil && platform.TPM != nil {
		opener = platformTPMOpener(platform)
	}
	s := &TPMTokenStrategy{
		platform: platform,
		logger:   logger,
		unsealer: newTokenUnsealer(logger, opener),
		// 0: ahead of TPM-PCR (1). The token is what SDK enrolment wrote
		// under the PCR policy, so it is the current enrolment when present;
		// without a token CanUnlock is false and TPM-PCR (ESP) runs next.
		priority:            0,
		sealPending:         firstbootSealPending,
		upgradeSealsPending: upgradeSealsOnESP,
	}
	s.extendPCR = func(ctx context.Context) error {
		return extendPlatformPCRWith(ctx, s.platform, s.logger)
	}
	return s
}

// firstbootSealPending is true while the installer container is still on
// the ESP or mounted: the firstboot seal has not been proven by a TPM-PCR
// unlock yet.
func firstbootSealPending() bool {
	for _, p := range []string{
		filepath.Join(pcrEfiMountPoint, "tpm2", "installer.luks"),
		"/mnt/installer/luks-key.bin",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// upgradeSealsOnESP reports whether the insecure upgrade seals are still on
// the mounted ESP.
func upgradeSealsOnESP() bool { return upgradeSealsUnder(pcrEfiMountPoint) }

// upgradeSealsUnder reports whether either upgrade seal file exists under root.
func upgradeSealsUnder(root string) bool {
	for _, name := range []string{pcrUpgradePublicFile, pcrUpgradePrivateFile} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return true
		}
	}
	return false
}

// Name returns StrategyNameTPMToken.
func (s *TPMTokenStrategy) Name() string { return StrategyNameTPMToken }

// Priority runs the token strategy ahead of the ESP TPM strategies.
func (s *TPMTokenStrategy) Priority() int { return s.priority }

// SetUnsealer replaces the TPM unsealer. A nil unsealer makes CanUnlock
// false, so the chain moves on to the next strategy.
func (s *TPMTokenStrategy) SetUnsealer(u TokenUnsealer) { s.unsealer = u }

type tpmTokenSlot struct {
	slot  int
	token *luks.Token
}

// tokenSlots lists the keyslots systemd-tpm2 tokens name, in token order.
func (s *TPMTokenStrategy) tokenSlots(ctx context.Context, volume *luks.VolumeConfig) []tpmTokenSlot {
	if s.platform == nil || s.platform.LUKS == nil {
		return nil
	}
	tokens, ok := s.platform.LUKS.(luks.HandlerWithTokens)
	if !ok {
		return nil
	}
	list, err := tokens.TokenList(ctx, volume.DevicePath)
	if err != nil {
		s.logger.Warnf("TPM token: reading LUKS2 tokens of %s: %v", volume.DevicePath, err)
		return nil
	}
	ids := make([]int, 0, len(list))
	for id := range list {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var out []tpmTokenSlot
	seen := map[int]bool{}
	for _, id := range ids {
		token := list[id]
		if token == nil || token.Type != tpmTokenType || token.TPM2Blob == "" {
			continue
		}
		for _, ks := range token.Keyslots {
			idx, err := strconv.Atoi(ks)
			if err != nil || idx < 0 || seen[idx] {
				continue
			}
			seen[idx] = true
			out = append(out, tpmTokenSlot{slot: idx, token: token})
		}
	}
	return out
}

// CanUnlock is true when an unsealer exists and the header holds a
// systemd-tpm2 token naming a keyslot.
func (s *TPMTokenStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	if s.unsealer == nil {
		s.logger.Debug("TPM token: no unsealer")
		return false
	}
	if s.sealPending != nil && s.sealPending() {
		s.logger.Info("TPM token: firstboot seal not yet confirmed; leaving the unlock to TPM-PCR")
		return false
	}
	if s.upgradeSealsPending != nil && s.upgradeSealsPending() {
		s.logger.Info("TPM token: upgrade seals present on the ESP; deferring to TPM-PCR so it removes them")
		return false
	}
	return len(s.tokenSlots(ctx, volume)) > 0
}

// Unlock unseals each token and opens its keyslot. A failed unseal or
// open returns an error so the chain moves on.
func (s *TPMTokenStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	if s.unsealer == nil {
		return ErrTPMTokenUnsealerUnavailable
	}
	// Enrolment sealed against the runtime PCRs, after the platform PCR
	// carries the golden measurement; restore that state first. A failed
	// extension only fails tokens bound to the platform PCR, so the
	// unseal below still decides.
	if s.extendPCR != nil {
		if err := s.extendPCR(ctx); err != nil {
			s.logger.Warnf("TPM token: extending the platform PCR: %v", err)
		}
	}
	var errs []error
	for _, ts := range s.tokenSlots(ctx, volume) {
		if err := ctx.Err(); err != nil {
			return err
		}
		pass, err := s.unsealer.Unseal(ctx, ts.token)
		if err != nil {
			s.logger.Warnf("TPM token: unseal for slot %d failed: %v", ts.slot, err)
			errs = append(errs, fmt.Errorf("slot %d: unseal: %w", ts.slot, err))
			continue
		}
		slot := ts.slot
		err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, pass, &luks.OpenOptions{
			AllowDiscards: volume.AllowDiscards,
			Timeout:       volume.Timeout,
			KeySlot:       &slot,
		})
		for i := range pass {
			pass[i] = 0
		}
		if err == nil {
			s.logger.Infof("Unlocked %s with the systemd-tpm2 token slot %d", volume.DevicePath, slot)
			return nil
		}
		errs = append(errs, fmt.Errorf("slot %d: open: %w", slot, err))
	}
	if len(errs) == 0 {
		return &MessageError{Msg: "no systemd-tpm2 token slot"}
	}
	return errors.Join(append([]error{&MessageError{Msg: "all systemd-tpm2 token slots failed"}}, errs...)...)
}

// Install is not supported: TPM enrolment writes the token through the
// LUKS backend, not the initrd.
func (s *TPMTokenStrategy) Install(context.Context, *luks.VolumeConfig, []byte) error {
	return &MessageError{Msg: "TPM token enrolment runs through the LUKS backend"}
}

// xkmsTokenUnsealer unseals with the go-xkms TPM sealer, the same sealer
// the LUKS backend's TPM enrolment seals with (defaultLUKSTPMHandler).
// pkg/storage/luks.Token carries the systemd-tpm2 JSON field names, so the
// token marshals to the payload UnsealPassphrase reads.
type xkmsTokenUnsealer struct {
	sealer *xkmsluks.TPMSealer
}

func (u *xkmsTokenUnsealer) Unseal(ctx context.Context, token *luks.Token) ([]byte, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("initrd: encoding the systemd-tpm2 token: %w", err)
	}
	return u.sealer.UnsealPassphrase(ctx, payload)
}

// newTokenUnsealer opens the go-xkms sealer over opener (the platform's TPM,
// or the SDK default device when the platform has none), or returns nil
// when it cannot be built.
func newTokenUnsealer(logger *logging.Logger, opener xkmsluks.TPMOpener) TokenUnsealer {
	sealer, err := xkmsluks.NewTPMSealer(logger.Slog(), opener)
	if err != nil {
		logger.Debugf("TPM token: sealer unavailable: %v", err)
		return nil
	}
	return &xkmsTokenUnsealer{sealer: sealer}
}

// platformTPMOpener hands the sealer the platform's own TPM transport (the
// device the boot manager detected). The sealer closes its transport after
// each command batch, but the platform owns and closes its transport, so
// the lent transport's Close is a no-op. A nil platform TPM or transport
// answers xkmsluks.ErrTPMNoTransport.
func platformTPMOpener(platform *Platform) xkmsluks.TPMOpener {
	return xkmsluks.TPMOpenerFunc(func(context.Context) (transport.TPMCloser, error) {
		if platform == nil || platform.TPM == nil {
			return nil, xkmsluks.ErrTPMNoTransport
		}
		tpm := platform.TPM.Transport()
		if tpm == nil {
			return nil, xkmsluks.ErrTPMNoTransport
		}
		return platformSharedTPM{tpm}, nil
	})
}

// platformSharedTPM lends the platform's transport; Close leaves it open.
type platformSharedTPM struct{ transport.TPM }

// Close is a no-op: the platform owns and closes its transport.
func (platformSharedTPM) Close() error { return nil }
