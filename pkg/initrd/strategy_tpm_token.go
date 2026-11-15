package initrd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

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

// tokenUnsealer unseals the passphrase a systemd-tpm2 token carries.
type tokenUnsealer interface {
	Unseal(ctx context.Context, token *luks.Token) ([]byte, error)
}

// TPMTokenStrategy unlocks a volume through the keyslot a systemd-tpm2
// header token names, unsealing the token's blob with the TPM. It is the
// boot side of the SDK TPM enrolment wired in WireSDKBackends.
type TPMTokenStrategy struct {
	platform *Platform
	logger   *logging.Logger
	unsealer tokenUnsealer
	priority int
}

// NewTPMTokenStrategy returns the strategy with the default TPM unsealer.
func NewTPMTokenStrategy(platform *Platform, logger *logging.Logger) *TPMTokenStrategy {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &TPMTokenStrategy{
		platform: platform,
		logger:   logger,
		unsealer: newDefaultTokenUnsealer(logger),
		priority: 5,
	}
}

// Name returns StrategyNameTPMToken.
func (s *TPMTokenStrategy) Name() string { return StrategyNameTPMToken }

// Priority runs the token strategy ahead of the ESP TPM strategies.
func (s *TPMTokenStrategy) Priority() int { return s.priority }

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
	return len(s.tokenSlots(ctx, volume)) > 0
}

// Unlock unseals each token and opens its keyslot. A failed unseal or
// open returns an error so the chain moves on.
func (s *TPMTokenStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	if s.unsealer == nil {
		return ErrTPMTokenUnsealerUnavailable
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

// newDefaultTokenUnsealer opens the go-xkms sealer on the default TPM
// transport, or returns nil when it cannot be built.
func newDefaultTokenUnsealer(logger *logging.Logger) tokenUnsealer {
	sealer, err := xkmsluks.NewTPMSealer(logger.Slog(), xkmsluks.DefaultTPMOpener())
	if err != nil {
		logger.Debugf("TPM token: sealer unavailable: %v", err)
		return nil
	}
	return &xkmsTokenUnsealer{sealer: sealer}
}
