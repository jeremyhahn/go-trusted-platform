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

// canonical_auth.go wires the canonical "auth" command group on
// platformctl per docs/architecture/08-bootstrap-auth-architecture.md
// §6. The handlers delegate to the platform SDK
// `sdk/go/services/auth.Client` (which itself wraps the go-quicbaas SDK
// Security().Auth().Factors() M10 surface backed by go-qrdb's M14
// User N-AuthFactor service).
//
// Per spec §5d the only cross-project import allowed from
// pkg/cli/commands is go-quicbaas/sdk/go (transitively, via the
// platform sdk/go/services/auth wrapper). Direct imports of
// go-xkms/pkg or go-qrdb/pkg are forbidden.
package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	authsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/auth"
)

// PendingCredentialBackendError is emitted by "credential" subcommand
// handlers before the credential service surface ships in the SDK.
type PendingCredentialBackendError struct {
	Op string
}

// Error returns a human-readable description.
func (e *PendingCredentialBackendError) Error() string {
	return e.Op + " is not yet wired to the SDK CredentialService"
}

// AuthClientFactory builds an auth Service. The default factory dials
// go-quicbaas using an address resolved from the active CLI context;
// tests override it with an in-process implementation.
type AuthClientFactory func(ctx context.Context, flags *cli.CommonFlags) (authsvc.Service, error)

// authClientFactory is the active factory used by handlers.
var authClientFactory AuthClientFactory = defaultAuthClientFactory

// SetAuthClientFactory installs a new factory and returns a restorer
// that the caller invokes via defer in tests.
func SetAuthClientFactory(f AuthClientFactory) func() {
	prev := authClientFactory
	authClientFactory = f
	return func() { authClientFactory = prev }
}

// defaultAuthClientFactory dials go-quicbaas using the active CLI
// context. Address precedence: PLATFORMCTL_QUICBAAS_ADDR env, then
// remote server URL, then local Unix socket.
func defaultAuthClientFactory(_ context.Context, flags *cli.CommonFlags) (authsvc.Service, error) {
	addr, opts, err := resolveQuicBaaSAddress(flags)
	if err != nil {
		return nil, err
	}
	return authsvc.NewClient(authsvc.ClientConfig{Address: addr, Options: opts})
}

// resolveQuicBaaSAddress determines the quicbaas SDK address from the
// CLI context plus PLATFORMCTL_QUICBAAS_ADDR env var. The env var
// takes precedence; otherwise local-context contexts default to the
// platformd-colocated socket "/run/quicbaas.sock", and remote
// contexts use the configured server URL.
func resolveQuicBaaSAddress(flags *cli.CommonFlags) (string, []quicbaas.Option, error) {
	if env := strings.TrimSpace(os.Getenv("PLATFORMCTL_QUICBAAS_ADDR")); env != "" {
		opts := transportOptions(env)
		return env, opts, nil
	}
	if flags == nil || flags.GetContext == nil {
		return "/run/quicbaas.sock", []quicbaas.Option{quicbaas.WithUnix("/run/quicbaas.sock")}, nil
	}
	ctx, err := flags.GetContext()
	if err != nil {
		return "", nil, err
	}
	switch ctx.Type {
	case cli.ContextTypeLocal:
		path := "/run/quicbaas.sock"
		return path, []quicbaas.Option{quicbaas.WithUnix(path)}, nil
	case cli.ContextTypeRemote:
		if ctx.Remote == nil || ctx.Remote.Server == "" {
			return "", nil, fmt.Errorf("auth: remote context %q has no server configured", ctx.Name)
		}
		return ctx.Remote.Server, transportOptions(ctx.Remote.Server), nil
	case cli.ContextTypeEmbedded:
		return "embedded", nil, fmt.Errorf("auth: embedded context cannot dial quicbaas (set PLATFORMCTL_QUICBAAS_ADDR)")
	default:
		return "", nil, fmt.Errorf("auth: unsupported context type %q", ctx.Type)
	}
}

// transportOptions selects the appropriate quicbaas transport option
// from an address string.
func transportOptions(addr string) []quicbaas.Option {
	switch {
	case strings.HasSuffix(addr, ".sock"):
		return []quicbaas.Option{quicbaas.WithUnix(addr)}
	case strings.HasPrefix(addr, "https://") || strings.HasPrefix(addr, "http://"):
		return []quicbaas.Option{quicbaas.WithREST()}
	default:
		// Default to gRPC.
		return nil
	}
}

// NewAuthCommand builds the canonical "auth" command group.
func NewAuthCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "User authentication and N-factor management",
		Long: `User authentication operations.

  login                 Authenticate the active session
  factor list           List enrolled factors for the active user
  factor add            Enroll a new factor (mTLS, FIDO2, PIV, etc.)
  factor remove         Remove an enrolled factor by id
  factor rotate         Rotate an enrolled factor's key material
  factor relabel        Relabel an enrolled factor

The factor subcommands implement the N-factor model documented in
docs/architecture/08-bootstrap-auth-architecture.md §5e and delegate
to the quicbaas SDK Security().Auth().Factors() surface (M10 + M14).`,
	}

	cmd.AddCommand(newAuthLoginCommand(getFlags))
	cmd.AddCommand(newAuthFactorCommand(getFlags))
	return cmd
}

// newAuthLoginCommand implements "auth login [--method mtls|fido2|piv]
// [--factor <id>] [--username <subject>] [--client-cert <path>]
// [--device <id>] [--reader <name>] [--slot 9a] [--pin <pin>]
// [--rp-id <id>] [--save-token] [--token-path <path>]".
func newAuthLoginCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &authLoginOptions{}
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the active session",
		Long: `Authenticate using one of the enrolled factors.

The --method flag selects the auth method (mtls, fido2, piv); when
omitted the CLI auto-discovers an available method by probing for a
client certificate at the default path, then attached FIDO2 devices,
then PC/SC readers.

The --factor flag pins the login to a specific enrolled factor when the
user has multiple factors of the same type registered.

Per docs/architecture/08-bootstrap-auth-architecture.md §5c the login
flow is vendor-agnostic: the same code path authenticates a YubiKey, a
SoloKey, a Nitrokey, TouchID, Windows Hello, and any other CTAP2 /
PIV-compliant device.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuthLogin(cmd.Context(), getFlags(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Method, "method", "", "Auth method: mtls | fido2 | piv (default: auto-discover)")
	cmd.Flags().StringVar(&opts.FactorID, "factor", "", "Enrolled factor id")
	cmd.Flags().StringVar(&opts.Username, "username", "", "Username (subject) for login")
	cmd.Flags().StringVar(&opts.ClientCertPath, "client-cert", "", "Client certificate PEM path (--method mtls)")
	cmd.Flags().StringVar(&opts.Device, "device", "", "FIDO2 device id (--method fido2)")
	cmd.Flags().StringVar(&opts.RPID, "rp-id", "", "WebAuthn relying-party id (--method fido2; default: platform)")
	cmd.Flags().StringVar(&opts.Reader, "reader", "", "PC/SC reader name (--method piv)")
	cmd.Flags().StringVar(&opts.Slot, "slot", "9a", "PIV slot id (--method piv; default 9a)")
	cmd.Flags().StringVar(&opts.PIN, "pin", "", "PIV User PIN (--method piv; falls back to PLATFORMCTL_USER_PIN)")
	cmd.Flags().BoolVar(&opts.SaveToken, "save-token", false, "Persist the issued session token to --token-path")
	cmd.Flags().StringVar(&opts.TokenPath, "token-path", "", "Where to write the session token (default: ~/.platformctl/session.token)")
	return cmd
}

// authLoginOptions consolidates the canonical "auth login" flag set in
// a single struct so the command builder and handler stay aligned.
type authLoginOptions struct {
	Method         string
	FactorID       string
	Username       string
	ClientCertPath string
	Device         string
	RPID           string
	Reader         string
	Slot           string
	PIN            string
	SaveToken      bool
	TokenPath      string
}

// newAuthFactorCommand builds the "auth factor" subcommand group.
func newAuthFactorCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "factor",
		Short: "N-factor management (list, add, remove, rotate, relabel)",
	}
	cmd.AddCommand(newAuthFactorListCommand(getFlags))
	cmd.AddCommand(newAuthFactorAddCommand(getFlags))
	cmd.AddCommand(newAuthFactorRemoveCommand(getFlags))
	cmd.AddCommand(newAuthFactorRotateCommand(getFlags))
	cmd.AddCommand(newAuthFactorRelabelCommand(getFlags))
	return cmd
}

// newAuthFactorListCommand implements "auth factor list [--user]".
func newAuthFactorListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled factors for the active user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuthFactorList(cmd.Context(), getFlags(), user)
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "Filter by user/subject (admin)")
	return cmd
}

// newAuthFactorAddCommand implements "auth factor add".
func newAuthFactorAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := &authsvc.AddFactorRequest{}
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Enroll a new factor",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuthFactorAdd(cmd.Context(), getFlags(), req)
		},
	}
	bindAddFactorFlags(cmd, req)
	return cmd
}

// newAuthFactorRemoveCommand implements "auth factor remove
// <factor-id> [--force]".
func newAuthFactorRemoveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <factor-id>",
		Short: "Remove an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &authsvc.ErrMissingFactorID{Op: "auth factor remove"}
			}
			return runAuthFactorRemove(cmd.Context(), getFlags(), args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Allow removing the last factor (admin)")
	return cmd
}

// newAuthFactorRotateCommand implements "auth factor rotate
// <factor-id> --type --label ...".
func newAuthFactorRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := &authsvc.AddFactorRequest{}
	cmd := &cobra.Command{
		Use:   "rotate <factor-id>",
		Short: "Rotate an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &authsvc.ErrMissingFactorID{Op: "auth factor rotate"}
			}
			return runAuthFactorRotate(cmd.Context(), getFlags(), args[0], req)
		},
	}
	bindAddFactorFlags(cmd, req)
	return cmd
}

// newAuthFactorRelabelCommand implements "auth factor relabel
// <factor-id> --label <name>".
func newAuthFactorRelabelCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "relabel <factor-id>",
		Short: "Relabel an enrolled factor",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &authsvc.ErrMissingFactorID{Op: "auth factor relabel"}
			}
			return runAuthFactorRelabel(cmd.Context(), getFlags(), args[0], label)
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "New human-readable label")
	return cmd
}

// bindAddFactorFlags wires the canonical add/rotate flag set onto a
// cobra command.
func bindAddFactorFlags(cmd *cobra.Command, req *authsvc.AddFactorRequest) {
	cmd.Flags().StringVar(&req.Type, "type", "", "Factor type: mtls | fido2 | piv")
	cmd.Flags().StringVar(&req.Label, "label", "", "Human-readable factor label (required)")
	cmd.Flags().StringVar(&req.User, "user", "", "Subject/user (default: current authenticated user)")
	cmd.Flags().StringVar(&req.Tenant, "tenant", "", "Tenant ID (optional)")
	cmd.Flags().StringVar(&req.CertPath, "cert", "", "Certificate PEM path (--type mtls)")
	cmd.Flags().StringVar(&req.FIDO2Device, "device", "", "FIDO2 device id (--type fido2; default first connected)")
	cmd.Flags().StringVar(&req.PIVReader, "reader", "", "PC/SC reader name (--type piv)")
	cmd.Flags().StringVar(&req.PIVSlot, "slot", "9a", "PIV slot id (--type piv; default 9a)")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// runAuthFactorList lists enrolled factors.
func runAuthFactorList(ctx context.Context, flags *cli.CommonFlags, user string) error {
	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	resp, err := svc.ListFactors(ctx, user)
	if err != nil {
		return err
	}

	out := os.Stdout
	if resp == nil || len(resp.Enrollments) == 0 {
		fmt.Fprintln(out, "(no enrolled factors)")
		return nil
	}
	fmt.Fprintln(out, "ID\tTYPE\tUSER\tTENANT\tENROLLED\tREVOKED")
	for _, e := range resp.Enrollments {
		revoked := "-"
		if e.RevokedAt != nil {
			revoked = e.RevokedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.EnrollmentID, e.FactorName, e.UserID, e.TenantID,
			e.EnrolledAt.Format(time.RFC3339), revoked)
	}
	return nil
}

// runAuthFactorAdd enrolls a factor.
func runAuthFactorAdd(ctx context.Context, flags *cli.CommonFlags, req *authsvc.AddFactorRequest) error {
	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	resp, err := svc.AddFactor(ctx, req)
	if err != nil {
		return err
	}
	out := os.Stdout
	fmt.Fprintf(out, "Enrollment ID: %s\n", resp.EnrollmentID)
	fmt.Fprintf(out, "Type:          %s\n", resp.FactorName)
	fmt.Fprintf(out, "User:          %s\n", resp.UserID)
	if resp.TenantID != "" {
		fmt.Fprintf(out, "Tenant:        %s\n", resp.TenantID)
	}
	fmt.Fprintf(out, "Enrolled At:   %s\n", resp.EnrolledAt.Format(time.RFC3339))
	if req.Label != "" {
		fmt.Fprintf(out, "Label:         %s\n", req.Label)
	}
	return nil
}

// runAuthFactorRemove revokes a factor.
func runAuthFactorRemove(ctx context.Context, flags *cli.CommonFlags, factorID string, force bool) error {
	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	if err := svc.RemoveFactor(ctx, factorID, force); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "OK")
	return nil
}

// runAuthFactorRotate rotates a factor.
func runAuthFactorRotate(ctx context.Context, flags *cli.CommonFlags, oldID string, req *authsvc.AddFactorRequest) error {
	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	resp, err := svc.RotateFactor(ctx, oldID, req)
	if err != nil {
		return err
	}
	out := os.Stdout
	fmt.Fprintf(out, "Old factor revoked: %s\n", oldID)
	fmt.Fprintf(out, "New enrollment ID:  %s\n", resp.EnrollmentID)
	fmt.Fprintf(out, "Type:               %s\n", resp.FactorName)
	return nil
}

// runAuthFactorRelabel updates a factor label.
func runAuthFactorRelabel(ctx context.Context, flags *cli.CommonFlags, factorID, label string) error {
	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	if err := svc.RelabelFactor(ctx, factorID, label); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "OK")
	return nil
}

// runAuthLogin executes a type-dispatched login by delegating to the
// platform auth SDK service. PIN/token flags are viper-resolved so the
// operator can supply them via PLATFORMCTL_USER_PIN /
// PLATFORMCTL_TOKEN_PATH environment variables.
func runAuthLogin(ctx context.Context, flags *cli.CommonFlags, opts *authLoginOptions) error {
	if opts == nil {
		opts = &authLoginOptions{}
	}
	resolveAuthLoginEnv(opts)

	svc, err := authClientFactory(ctx, flags)
	if err != nil {
		return err
	}
	defer func() { _ = svc.Close() }()

	resp, err := svc.Login(ctx, &authsvc.LoginRequest{
		Username:       opts.Username,
		Method:         opts.Method,
		FactorID:       opts.FactorID,
		ClientCertPath: opts.ClientCertPath,
		RPID:           opts.RPID,
		Device:         opts.Device,
		Reader:         opts.Reader,
		Slot:           opts.Slot,
		PIN:            opts.PIN,
	})
	if err != nil {
		return err
	}

	out := os.Stdout
	fmt.Fprintf(out, "User:       %s (%s)\n", resp.Username, resp.UserID)
	fmt.Fprintf(out, "Token:      %s\n", resp.Token)
	fmt.Fprintf(out, "Issued At:  %s\n", resp.IssuedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "Expires At: %s\n", resp.ExpiresAt.Format(time.RFC3339))

	if opts.SaveToken {
		path, werr := writeSessionToken(opts.TokenPath, resp.Token)
		if werr != nil {
			return werr
		}
		fmt.Fprintf(out, "Token saved to %s\n", path)
	}
	return nil
}

// resolveAuthLoginEnv fills in viper-bound environment variable values
// for any flag that was not explicitly supplied. The PLATFORMCTL_*
// prefix mirrors the binary name.
func resolveAuthLoginEnv(opts *authLoginOptions) {
	v := viper.New()
	v.SetEnvPrefix("PLATFORMCTL")
	v.AutomaticEnv()
	if opts.PIN == "" {
		opts.PIN = v.GetString("USER_PIN")
	}
	if opts.ClientCertPath == "" {
		opts.ClientCertPath = v.GetString("CLIENT_CERT")
	}
	if opts.TokenPath == "" {
		opts.TokenPath = v.GetString("TOKEN_PATH")
	}
}

// writeSessionToken persists the issued JWT to disk and returns the
// resolved path. Defaults to ~/.platformctl/session.token when the
// caller does not supply an explicit path.
func writeSessionToken(explicit, token string) (string, error) {
	path := explicit
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", &authsvc.ErrTokenWrite{Path: "", Cause: err}
		}
		path = filepath.Join(home, ".platformctl", "session.token")
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
		return "", &authsvc.ErrTokenWrite{Path: path, Cause: mkErr}
	}
	if wErr := os.WriteFile(path, []byte(token+"\n"), 0o600); wErr != nil {
		return "", &authsvc.ErrTokenWrite{Path: path, Cause: wErr}
	}
	return path, nil
}

// NewCredentialCommand builds the canonical "credential" command
// group per docs/architecture/08-bootstrap-auth-architecture.md §6.
func NewCredentialCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credential",
		Short: "Post-init credential operations (submit, list, rotate)",
	}
	for _, verb := range []struct{ use, short string }{
		{"submit", "Submit a new credential"},
		{"list", "List submitted credentials"},
		{"rotate", "Rotate an existing credential"},
	} {
		v := verb
		cmd.AddCommand(&cobra.Command{
			Use:   v.use,
			Short: v.short,
			Args:  cobra.ArbitraryArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return &PendingCredentialBackendError{Op: "credential " + v.use}
			},
		})
	}
	return cmd
}
