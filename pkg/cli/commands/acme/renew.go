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

package acme

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// renewFlags holds the flags for the renew command
type renewFlags struct {
	// Authorization flags
	authzType     string
	challengeType string
	directoryURL  string
	caCert        string
	email         string

	// Subject flags
	cn                 string
	organization       string
	organizationalUnit string
	country            string
	province           string
	locality           string
	streetAddress      string
	postalCode         string

	// SAN flags
	sansDNS    []string
	sansEmails []string
	sansIPs    []string
}

// newRenewCommand creates the renew subcommand for certificate renewal
func newRenewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	rf := &renewFlags{}

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Request or renew a certificate",
		Long: `Request a new certificate or renew an existing certificate.

This command initiates the ACME certificate issuance flow using
the specified authorization type and challenge. The certificate
request includes the subject and SANs from either command-line
flags or platform configuration.

Authorization types:
  - dns: Domain name authorization (default)
  - ip: IP address authorization
  - permanent-identifier: Device identifier authorization

Challenge types:
  - http-01: HTTP challenge (default)
  - dns-01: DNS challenge
  - endorse-01: Endorsement challenge
  - device-01: Device challenge
  - device-attest-01: Device attestation challenge

Examples:
  # Renew certificate for domain
  platformctl acme renew --cn example.com

  # Renew with specific algorithm and SANs
  platformctl acme renew --cn example.com --sans-dns www.example.com --sans-dns api.example.com

  # Renew using DNS challenge
  platformctl acme renew --cn example.com --challenge dns-01

  # Renew with full subject
  platformctl acme renew \
    --cn example.com \
    --organization "Example Corp" \
    --country US \
    --province California \
    --locality "San Francisco"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRenew(flags, rf)
		},
	}

	// Authorization flags
	cmd.Flags().StringVar(&rf.authzType, "authz", "dns", "authorization type (dns, ip, permanent-identifier)")
	cmd.Flags().StringVar(&rf.challengeType, "challenge", "http-01", "challenge type (http-01, dns-01, endorse-01, device-01, device-attest-01)")
	cmd.Flags().StringVar(&rf.directoryURL, "directory", "https://localhost:8443/api/v1/acme/directory", "ACME server directory URL")
	cmd.Flags().StringVar(&rf.caCert, "ca-cert", "ca-bundle.pem", "ACME server root certificate")
	cmd.Flags().StringVar(&rf.email, "email", "", "ACME account email address")

	// Subject flags
	cmd.Flags().StringVar(&rf.cn, "cn", "", "subject common name (CN)")
	cmd.Flags().StringVar(&rf.organization, "organization", "", "subject organization")
	cmd.Flags().StringVar(&rf.organizationalUnit, "organizational-unit", "", "subject organizational unit")
	cmd.Flags().StringVar(&rf.country, "country", "", "subject country")
	cmd.Flags().StringVar(&rf.province, "province", "", "subject province")
	cmd.Flags().StringVar(&rf.locality, "locality", "", "subject locality")
	cmd.Flags().StringVar(&rf.streetAddress, "street-address", "", "subject street address")
	cmd.Flags().StringVar(&rf.postalCode, "postal-code", "", "subject postal code")

	// SAN flags
	cmd.Flags().StringArrayVar(&rf.sansDNS, "sans-dns", []string{}, "Subject Alternative Name (SAN) DNS names")
	cmd.Flags().StringArrayVar(&rf.sansEmails, "sans-email", []string{}, "Subject Alternative Name (SAN) email addresses")
	cmd.Flags().StringArrayVar(&rf.sansIPs, "sans-ip", []string{}, "Subject Alternative Name (SAN) IP addresses")

	return cmd
}

// runRenew executes the renew command
func runRenew(flags *cli.CommonFlags, rf *renewFlags) error {
	if err := rf.validate(); err != nil {
		return err
	}
	return ErrACMEDaemonCallMissing{Command: "renew", Section: "§7.4 order and finalize"}
}

// authorizationTypes are the identifier types --authz accepts.
var authorizationTypes = map[string]struct{}{
	"dns":                  {},
	"ip":                   {},
	"permanent-identifier": {},
}

// challengeTypes are the challenge types --challenge accepts.
var challengeTypes = map[string]struct{}{
	"http-01":          {},
	"dns-01":           {},
	"endorse-01":       {},
	"device-01":        {},
	"device-attest-01": {},
}

// validate checks the order a renew would place: a known authorization and
// challenge type, an IP SAN for IP authorization, and at least one
// identifier (a CN or a SAN).
func (rf *renewFlags) validate() error {
	if _, ok := authorizationTypes[rf.authzType]; !ok {
		return ErrInvalidAuthorizationType{Type: rf.authzType}
	}
	if _, ok := challengeTypes[rf.challengeType]; !ok {
		return ErrInvalidChallengeType{Type: rf.challengeType}
	}
	if rf.authzType == "ip" && len(rf.sansIPs) == 0 {
		return ErrIPAuthorizationRequiresIP{}
	}
	if rf.cn == "" && len(rf.sansDNS) == 0 && len(rf.sansIPs) == 0 {
		return ErrMissingAuthorizationValue{}
	}
	return nil
}
