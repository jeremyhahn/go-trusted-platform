// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"encoding/base64"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// newAttestChallengeCommand creates the device attest-challenge command.
func newAttestChallengeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "attest-challenge <id>",
		Short: "Issue a single-use attestation challenge for a device",
		Long: `Ask the server for a single-use attestation challenge for a registered device.

The device quotes with the challenge's nonce as qualifying data, then the
evidence is sent with "platformctl device attest <id> --challenge-id
<challenge_id>". A challenge is consumed on the first attest, whatever the
result, and expires at expires_at.

Examples:
  platformctl device attest-challenge 123
  platformctl device attest-challenge 123 -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestChallenge(getFlags(), args[0])
		},
	}
}

// attestChallengeOutput is an issued challenge, shaped like the REST response.
type attestChallengeOutput struct {
	DeviceID    uint64    `json:"device_id"`
	ChallengeID string    `json:"challenge_id"`
	Nonce       []byte    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// runAttestChallenge asks the server for a challenge for a device and
// renders it.
func runAttestChallenge(flags *cli.CommonFlags, idStr string) error {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		return ErrInvalidDeviceID{ID: idStr}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	resp, err := deviceClient.IssueAttestationChallenge(base.Context(), id)
	if err != nil {
		if isNotFound(err) {
			return ErrDeviceNotFound{ID: id}
		}
		return ErrAttestChallengeFailed{ID: id, Cause: err}
	}

	out := attestChallengeOutput{
		DeviceID:    id,
		ChallengeID: resp.GetChallengeId(),
		Nonce:       resp.GetNonce(),
	}
	if ts := resp.GetExpiresAt(); ts != nil {
		out.ExpiresAt = ts.AsTime()
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printer := base.Printer()
		printer.PrintSuccess("Attestation challenge issued")
		printer.PrintKeyValue("ID", strconv.FormatUint(out.DeviceID, 10))
		printer.PrintKeyValue("Challenge ID", out.ChallengeID)
		printer.PrintKeyValue("Nonce", base64.StdEncoding.EncodeToString(out.Nonce))
		printer.PrintKeyValue("Expires At", out.ExpiresAt.UTC().Format(time.RFC3339))
		return nil
	}
	return base.Output(out)
}
