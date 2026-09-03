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

package admin

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// claimOptions are the flags shared by the claim commands.
//
// The endpoint and its TLS settings are RESOLVED, not simply read off the
// flags: an unset flag falls back to the active platformctl context, so
// `platformctl admin claim` reaches the same node every other platformctl
// command reaches. Explicit flags always win — an operator running the
// ceremony against a node they have no context for should not have to
// create one first.
type claimOptions struct {
	api        string
	bundleDir  string
	caFile     string
	console    string
	serverName string

	// getFlags reaches the active CLI context. Nil in tests that exercise
	// the flag path directly, and tolerated: resolution then falls back to
	// the loopback default, exactly as it does when no context is
	// configured.
	getFlags func() *cli.CommonFlags
}

func (o *claimOptions) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.api, "api", "",
		"platform REST endpoint serving the claim ceremony "+
			"(default: the active context's server, else "+DefaultAPI+")")
	cmd.Flags().StringVar(&o.bundleDir, "bundle", DefaultBundleDir,
		"directory holding the first-boot admin.crt and admin.key")
	cmd.Flags().StringVar(&o.caFile, "ca", "",
		"PEM bundle the platform's TLS certificate must chain to "+
			"(default: the active context's CA, else the host trust store)")
}

// resolve fills the endpoint and TLS settings the flags left unset from the
// active platformctl context.
//
// The claim ceremony is REST-only by construction: its routes run BEFORE
// any session exists, so there is nothing for the session-bearing SDK
// client to carry (docs/auth/api.md §2b). A context therefore contributes
// its ADDRESS and TLS settings here rather than its transport, and a local
// context — whose daemon is on this host — resolves to the loopback REST
// endpoint.
//
// A remote context that names a NON-REST address is refused rather than
// guessed at. `Context.ResolveProtocol` treats a server that does not begin
// http:// or https:// as gRPC, and remote contexts default to gRPC, so
// copying such a value into an HTTPS client would either fail with a
// confusing URL error or — worse, if a scheme were bolted on and a port
// assumed — reach some other service on that host. The ceremony hands a
// claim token to whatever answers, which is why this command has no
// --insecure escape hatch either; silently addressing an unintended
// endpoint is the same class of mistake. The operator is told to pass
// --api instead.
func (o *claimOptions) resolve() error {
	active := o.activeRemote()
	if active != nil {
		if o.api == "" && active.Server != "" {
			if !isRESTEndpoint(active.Server) {
				return ErrContextNotREST{Server: active.Server}
			}
			o.api = active.Server
		}
		if o.caFile == "" {
			o.caFile = active.CACert
		}
		o.serverName = active.ServerName
	}
	if o.api == "" {
		o.api = DefaultAPI
	}
	return nil
}

// activeRemote returns the active context's remote settings, or nil when
// there is no usable remote context.
//
// A missing, unreadable or local context is not an error: the loopback
// default is the on-node case this command was written for.
func (o *claimOptions) activeRemote() *cli.RemoteContext {
	if o.getFlags == nil {
		return nil
	}
	flags := o.getFlags()
	if flags == nil || flags.GetContext == nil {
		return nil
	}
	active, err := flags.GetContext()
	if err != nil || active == nil {
		return nil
	}
	return active.Remote
}

// isRESTEndpoint reports whether addr is an HTTP(S) URL, which is the only
// shape the claim ceremony can dial. It mirrors the test
// `Context.ResolveProtocol` uses to tell a REST server from a gRPC one, so
// the CLI and the context agree on what "REST" means.
func isRESTEndpoint(addr string) bool {
	return strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://")
}

// newClaimCommand builds "platformctl admin claim".
func newClaimCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &claimOptions{getFlags: getFlags}
	cmd := &cobra.Command{
		Use:   "claim",
		Short: "Prove possession of the first-boot admin credential",
		Long: `Prove possession of this node's first-boot admin credential and obtain a
single-use claim token.

The command reads admin.crt and admin.key from the credential bundle, asks
the daemon for a one-time challenge, signs it with the admin key, and
exchanges the signature for a claim token. Take that token to the console
to register your passkey and finish the ceremony.

The certificate is the sole bootstrap anchor for the system admin — there
is no invitation path for this identity.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaim(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	opts.bind(cmd)
	cmd.Flags().StringVar(&opts.console, "console", "",
		"console base URL to print in the finish instructions (default: derived from --api)")
	return cmd
}

// newClaimStatusCommand builds "platformctl admin claim-status".
func newClaimStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &claimOptions{getFlags: getFlags}
	cmd := &cobra.Command{
		Use:   "claim-status",
		Short: "Report whether this node's admin identity has been claimed",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClaimStatus(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	opts.bind(cmd)
	return cmd
}

func runClaimStatus(ctx context.Context, out io.Writer, opts *claimOptions) error {
	if err := opts.resolve(); err != nil {
		return err
	}
	client, err := newClaimClient(opts.api, opts.caFile, opts.serverName)
	if err != nil {
		return err
	}
	status, err := client.status(ctx)
	if err != nil {
		return err
	}
	state := "unclaimed"
	if status.Claimed {
		state = "claimed"
	}
	fmt.Fprintf(out, "admin identity: %s\ntenant:         %s\nstate:          %s\n",
		status.Username, status.TenantID, state)
	return nil
}

func runClaim(ctx context.Context, out io.Writer, opts *claimOptions) error {
	if err := opts.resolve(); err != nil {
		return err
	}
	client, err := newClaimClient(opts.api, opts.caFile, opts.serverName)
	if err != nil {
		return err
	}
	// Check first so an operator on an already-claimed node gets a clear
	// answer instead of a rejected proof.
	status, err := client.status(ctx)
	if err != nil {
		return err
	}
	if status.Claimed {
		return ErrAlreadyClaimed{Username: status.Username}
	}

	credential, err := loadBundle(opts.bundleDir)
	if err != nil {
		return err
	}
	challenge, err := client.challenge(ctx)
	if err != nil {
		return err
	}
	signature, err := credential.sign([]byte(challenge.Challenge))
	if err != nil {
		return err
	}
	claim, err := client.verify(ctx, verifyRequest{
		Challenge:      challenge.Challenge,
		CertificatePEM: string(credential.certPEM),
		Signature:      signature,
	})
	if err != nil {
		return err
	}

	console := opts.console
	if console == "" {
		console = strings.TrimSuffix(opts.api, "/")
	}
	fmt.Fprintf(out, `Possession of the first-boot admin credential confirmed.

  identity:    %s (subject %s)
  tenant:      %s
  claim token: %s
  expires:     %s

Finish the ceremony in the console within the window above:

  1. open %s/setup/admin-claim
  2. paste the claim token
  3. register your passkey when the browser prompts

The passkey becomes an additional auth factor on the existing certificate-
based admin identity; the certificate remains the bootstrap anchor. After
this, sign in to the console as %s with that authenticator.
`,
		status.Username, credential.cert.Subject.CommonName, status.TenantID,
		claim.ClaimToken, claim.ExpiresAt.Format("2006-01-02 15:04:05 MST"),
		console, status.Username)
	return nil
}
