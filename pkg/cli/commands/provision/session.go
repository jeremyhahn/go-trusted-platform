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

package provision

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	provisionsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// sessionAPI is the slice of the provisioning SDK client the session verbs
// use. Tests inject a fake via SetSessionClientFactory; production code goes
// through the platform SDK client (base.Client().ConfigDelivery()), which
// works over every SDK transport (gRPC, Unix, REST, QUIC, MCP, embedded).
type sessionAPI interface {
	ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error)
	GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error)
	FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error)
	PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error)
}

// sessionClientFactory builds a sessionAPI from a BaseCommand. Tests
// override this so the session verbs can be exercised without dialing a
// live daemon.
type sessionClientFactory func(base *cli.BaseCommand) (sessionAPI, error)

// activeSessionClientFactory is the factory currently in use.
var activeSessionClientFactory sessionClientFactory = defaultSessionClientFactory

// SetSessionClientFactory installs a new session client factory and returns
// a restorer that the caller invokes via defer. Intended for in-process
// tests; production code MUST NOT call this.
func SetSessionClientFactory(f sessionClientFactory) func() {
	prev := activeSessionClientFactory
	activeSessionClientFactory = f
	return func() { activeSessionClientFactory = prev }
}

// defaultSessionClientFactory dials the daemon via the platform SDK Client
// and wraps its ConfigDelivery client in the provisioning service client.
func defaultSessionClientFactory(base *cli.BaseCommand) (sessionAPI, error) {
	return provisionsvc.NewClientFromGRPC(base.Client().ConfigDelivery()), nil
}

// newSessionCommand creates the session subcommand tree for provisioning
// session management.
func newSessionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage provisioning sessions",
		Long: `Manage pending provisioning sessions awaiting operator fulfillment.

When a booting device has no matching configuration, the config delivery
service opens an interactive provisioning session. Operators list the
pending sessions, inspect them, and fulfill them by linking a device
profile; the polling device then receives its configuration.

Examples:
  # List all active provisioning sessions
  platformctl provision session list

  # Get a session by ID
  platformctl provision session get 6f1c2b3a

  # Link device profile 42 to a pending session
  platformctl provision session fulfill 6f1c2b3a --profile-id 42

  # Poll a session once; write the config when delivered
  platformctl provision session poll 6f1c2b3a --output /tmp/config.json`,
	}

	cmd.AddCommand(newSessionListCommand(getFlags))
	cmd.AddCommand(newSessionGetCommand(getFlags))
	cmd.AddCommand(newSessionFulfillCommand(getFlags))
	cmd.AddCommand(newSessionPollCommand(getFlags))

	return cmd
}

// newSessionListCommand creates the session list subcommand.
func newSessionListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List active provisioning sessions",
		Long: `List all active (non-expired) provisioning sessions awaiting
operator fulfillment.

Examples:
  platformctl provision session list
  platformctl provision session list -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionList(getFlags)
		},
	}
}

// newSessionGetCommand creates the session get subcommand.
func newSessionGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <session-id>",
		Short: "Get a provisioning session by ID",
		Long: `Get a provisioning session by its identifier.

Examples:
  platformctl provision session get 6f1c2b3a
  platformctl provision session get 6f1c2b3a -o json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionGet(getFlags, args[0])
		},
	}
}

// newSessionFulfillCommand creates the session fulfill subcommand.
func newSessionFulfillCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var profileID string

	cmd := &cobra.Command{
		Use:   "fulfill <session-id>",
		Short: "Link a device profile to a pending provisioning session",
		Long: `Fulfill a pending provisioning session by linking a device
profile to it. The device polling the session receives its configuration
on its next poll.

The profile ID is a uint64; pass it as a decimal string.

Examples:
  platformctl provision session fulfill 6f1c2b3a --profile-id 42`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionFulfill(getFlags, args[0], profileID)
		},
	}

	cmd.Flags().StringVar(&profileID, "profile-id", "", "device profile ID to link (required, decimal uint64)")

	return cmd
}

// newSessionPollCommand creates the session poll subcommand.
func newSessionPollCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "poll <session-id>",
		Short: "Poll a provisioning session once",
		Long: `Poll a pending provisioning session once. When the session has
been fulfilled the delivered configuration is printed (or written to
--output); otherwise the pending status is reported.

Examples:
  platformctl provision session poll 6f1c2b3a
  platformctl provision session poll 6f1c2b3a --output /tmp/config.json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionPoll(getFlags, args[0], output)
		},
	}

	cmd.Flags().StringVar(&output, "output", "", "write the delivered config JSON to this file")

	return cmd
}

// sessionInfo is the CLI output shape for a provisioning session. The
// uint64 profile ID serializes as a decimal string per the repo-wide
// convention for uint64 IDs in JSON output.
type sessionInfo struct {
	ID         string `json:"id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	ProfileID  uint64 `json:"profile_id,string"`
	Fulfilled  bool   `json:"fulfilled"`
	CreatedAt  string `json:"created_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// sessionToInfo converts a pb ProvisioningSession to the CLI output shape.
func sessionToInfo(s *platformv1.ProvisioningSession) sessionInfo {
	return sessionInfo{
		ID:         s.GetId(),
		EKSerial:   s.GetEkSerial(),
		MACAddress: s.GetMacAddress(),
		TenantID:   s.GetTenantId(),
		ProfileID:  s.GetProfileId(),
		Fulfilled:  s.GetFulfilled(),
		CreatedAt:  formatTimestamp(s.GetCreatedAt()),
		ExpiresAt:  formatTimestamp(s.GetExpiresAt()),
	}
}

// formatTimestamp renders a pb timestamp as RFC3339, or empty when unset.
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}

// openSessionClient constructs the BaseCommand and session client for a
// session verb. The caller must Close() the returned BaseCommand.
func openSessionClient(getFlags func() *cli.CommonFlags) (*cli.BaseCommand, sessionAPI, error) {
	base, err := cli.NewBaseCommand(getFlags())
	if err != nil {
		return nil, nil, err
	}
	client, err := activeSessionClientFactory(base)
	if err != nil {
		closeErr := base.Close()
		if closeErr != nil {
			return nil, nil, ErrSessionClientFailed{Cause: fmt.Errorf("%v (close: %v)", err, closeErr)}
		}
		return nil, nil, ErrSessionClientFailed{Cause: err}
	}
	return base, client, nil
}

// sessionListOutput fetches the active sessions and maps them to the CLI
// output shape. Separated from runSessionList so the client interaction is
// unit-testable without a daemon.
func sessionListOutput(ctx context.Context, client sessionAPI) ([]sessionInfo, error) {
	sessions, err := client.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]sessionInfo, 0, len(sessions))
	for _, s := range sessions {
		infos = append(infos, sessionToInfo(s))
	}
	return infos, nil
}

// runSessionList executes the session list verb.
func runSessionList(getFlags func() *cli.CommonFlags) error {
	base, client, err := openSessionClient(getFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	infos, err := sessionListOutput(base.Context(), client)
	if err != nil {
		return err
	}

	flags := getFlags()
	if flags != nil && flags.OutputFormat == cli.OutputFormatTable {
		printSessionTable(base.Printer(), infos)
		return nil
	}
	return base.Output(map[string]interface{}{
		"total":    len(infos),
		"sessions": infos,
	})
}

// sessionGetOutput fetches a single session and maps it to the CLI output
// shape.
func sessionGetOutput(ctx context.Context, client sessionAPI, sessionID string) (sessionInfo, error) {
	session, err := client.GetSession(ctx, sessionID)
	if err != nil {
		return sessionInfo{}, err
	}
	return sessionToInfo(session), nil
}

// runSessionGet executes the session get verb.
func runSessionGet(getFlags func() *cli.CommonFlags, sessionID string) error {
	base, client, err := openSessionClient(getFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	info, err := sessionGetOutput(base.Context(), client, sessionID)
	if err != nil {
		return err
	}
	return base.Output(info)
}

// parseProfileID validates and parses the --profile-id flag value.
func parseProfileID(profileID string) (uint64, error) {
	if profileID == "" {
		return 0, ErrProfileIDRequired{}
	}
	id, err := strconv.ParseUint(profileID, 10, 64)
	if err != nil {
		return 0, ErrInvalidProfileID{Value: profileID, Cause: err}
	}
	if id == 0 {
		return 0, ErrProfileIDRequired{}
	}
	return id, nil
}

// sessionFulfillOutput links the profile to the session and builds the CLI
// acknowledgment output.
func sessionFulfillOutput(ctx context.Context, client sessionAPI, sessionID string, profileID uint64) (map[string]string, error) {
	resp, err := client.FulfillSession(ctx, sessionID, profileID)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"session_id": sessionID,
		"profile_id": strconv.FormatUint(profileID, 10),
		"status":     resp.GetStatus(),
	}, nil
}

// runSessionFulfill executes the session fulfill verb.
func runSessionFulfill(getFlags func() *cli.CommonFlags, sessionID, profileID string) error {
	id, err := parseProfileID(profileID)
	if err != nil {
		return err
	}

	base, client, err := openSessionClient(getFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	out, err := sessionFulfillOutput(base.Context(), client, sessionID, id)
	if err != nil {
		return err
	}
	return base.Output(out)
}

// sessionPollOutput polls the session once and builds the CLI output. When
// the config has been delivered and output is non-empty the config JSON is
// written to that path (0600) instead of inlined in the result.
func sessionPollOutput(ctx context.Context, client sessionAPI, sessionID, output string) (map[string]interface{}, error) {
	resp, err := client.PollSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	delivered := resp.GetDelivered()
	if delivered == nil {
		status := resp.GetPendingStatus()
		if status == "" {
			status = "pending"
		}
		return map[string]interface{}{
			"session_id": sessionID,
			"status":     status,
		}, nil
	}

	if output != "" {
		if writeErr := os.WriteFile(output, delivered.GetConfigJson(), 0600); writeErr != nil {
			return nil, ErrConfigWriteFailed{Path: output, Cause: writeErr}
		}
		return map[string]interface{}{
			"session_id": sessionID,
			"status":     delivered.GetStatus(),
			"output":     output,
		}, nil
	}

	return map[string]interface{}{
		"session_id": sessionID,
		"status":     delivered.GetStatus(),
		"config":     string(delivered.GetConfigJson()),
	}, nil
}

// runSessionPoll executes the session poll verb (a single poll).
func runSessionPoll(getFlags func() *cli.CommonFlags, sessionID, output string) error {
	base, client, err := openSessionClient(getFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	out, err := sessionPollOutput(base.Context(), client, sessionID, output)
	if err != nil {
		return err
	}
	return base.Output(out)
}

// printSessionTable prints sessions in table format.
func printSessionTable(printer *cli.Printer, sessions []sessionInfo) {
	if len(sessions) == 0 {
		fmt.Println("No provisioning sessions found")
		return
	}

	table := cli.NewTableData("ID", "EK SERIAL", "MAC", "PROFILE ID", "FULFILLED", "EXPIRES")
	for _, s := range sessions {
		profileID := ""
		if s.ProfileID != 0 {
			profileID = strconv.FormatUint(s.ProfileID, 10)
		}
		table.AddRow(
			s.ID,
			s.EKSerial,
			s.MACAddress,
			profileID,
			strconv.FormatBool(s.Fulfilled),
			s.ExpiresAt,
		)
	}

	if err := printer.Print(*table); err != nil {
		printer.PrintError(err.Error())
	}
}
