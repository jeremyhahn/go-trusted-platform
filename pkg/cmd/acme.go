package cmd

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	acmeAuthzType     string
	acmeChallengeType string
	acmeDirectoryURL  string
	acmeCACert        string
	acmeAccountEmail  string

	acmeSubjectCN                 string
	acmeSubjectOrganization       string
	acmeSubjectOrganizationalUnit string
	acmeSubjectCountry            string
	acmeSubjectProvince           string
	acmeSubjectLocality           string
	acmeSubjectStreetAddress      string
	acmeSubjectPostalCode         string

	acmeSANSDNS    []string
	acmeSANSEmails []string
	acmeSANSIPs    []string

	// acmeAccountKID string
	// acmeOrderKID   string
)

func init() {

	acmeCmd.PersistentFlags().StringVar(&acmeAuthzType, "authz", acme.AuthzTypeDNS.String(), "The ACME authorization type (dns, ip, permanent-identifier)")
	acmeCmd.PersistentFlags().StringVar(&acmeChallengeType, "challenge", acme.ChallengeTypeHTTP01.String(), "The ACME challenge type (http-01, dns-01, endorse-01, device-01, device-attest-01")
	acmeCmd.PersistentFlags().StringVar(&acmeCACert, "ca-cert", "ca-bundle.pem", "The ACME server root certificate")
	acmeCmd.PersistentFlags().StringVar(&acmeDirectoryURL, "directory", "https://localhost:8443/api/v1/acme/directory", "The ACME server directory URL")

	acmeCmd.PersistentFlags().StringVar(&acmeAccountEmail, "email", "", "The ACME account email address")

	// PKIX Subject flags
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectCN, "cn", "", "The Subject Common Name (CN)")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectOrganization, "organization", "", "The Subject Organization")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectOrganizationalUnit, "organizational-unit", "", "The Subject Organization Unit")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectCountry, "country", "", "The Subject Country")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectProvince, "province", "", "The Subject Province")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectLocality, "locality", "", "The Subject Locality")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectStreetAddress, "street-address", "", "The Subject Street Address")
	acmeCmd.PersistentFlags().StringVar(&acmeSubjectPostalCode, "postal-code", "", "The Subject Postal Code")

	// SANS flags
	acmeCmd.PersistentFlags().StringArrayVar(&acmeSANSDNS, "sans-dns", []string{}, "Subject Alternative Name (SAN) DNS names")
	acmeCmd.PersistentFlags().StringArrayVar(&acmeSANSEmails, "sans-email", []string{}, "Subject Alternative Name (SAN) email addresses")
	acmeCmd.PersistentFlags().StringArrayVar(&acmeSANSIPs, "sans-ip", []string{}, "Subject Alternative Name (SAN) IP addresses")

	// // Account and Order Key ID flags
	// acmeCmd.PersistentFlags().StringVar(&acmeAccountKID, "account-kid", keystore.STORE_TPM2.String(), "The Key Store Module used for the ACME account private key")
	// acmeCmd.PersistentFlags().StringVar(&acmeOrderKID, "order-kid", keystore.STORE_TPM2.String(), "The Key Store Module used to place a new ACME order")

	rootCmd.AddCommand(acmeCmd)
}

var acmeCmd = &cobra.Command{
	Use:   "acme [action]",
	Short: "ACME certificate management",
	Long: `Performs x509 certificate management operations using the Automated
Certificate Management Environment (ACME) client`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {

		action := args[0]

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		switch action {

		case "download":
			if App.ACMEClient == nil {
				if err := App.InitACMEClient(InitParams.Initialize); err != nil {
					cmd.PrintErrln(err)
					return
				}
			}
			certs, err := App.ACMEClient.DownloadCertificates(
				App.WebServiceConfig.Certificate.ACME.ChallengeType,
				App.ServerKeyAttributes,
				false,
				App.WebServiceConfig.Certificate.ACME.CrossSigner)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			for _, cert := range certs {
				fmt.Println(certstore.ToString(cert))
			}

		case "register":
			var err error
			if acmeAccountEmail == "" {
				_, err = App.ACMEClient.RegisterAccount()
			} else {
				_, err = App.ACMEClient.RegisterAccountWithEmail(acmeAccountEmail)
			}
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			fmt.Println(keystore.PublicKeyToString(App.ACMEClient.AccountSigner().Public()))

		case "renew":
			if App.ACMEClient == nil {
				if err := App.InitACMEClient(InitParams.Initialize); err != nil {
					cmd.PrintErrln(err)
					return
				}
			}
			certReq := certificateRequest()
			cert, xsigned, err := App.ACMEClient.RequestCertificate(certReq, false)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			fmt.Println(certstore.ToString(cert))
			if xsigned != nil {
				fmt.Println(certstore.ToString(xsigned))
			}

		case "rotate-key":
			if App.ACMEClient == nil {
				if err := App.InitACMEClient(InitParams.Initialize); err != nil {
					cmd.PrintErrln(err)
					return
				}
			}
			if err := App.ACMEClient.KeyChange(); err != nil {
				cmd.PrintErrln(err)
				return
			}
			fmt.Println(keystore.PublicKeyToString(App.ACMEClient.AccountSigner().Public()))

		default:
			cmd.PrintErrln("Invalid command")
			return

		}

	},
}

func certificateRequest() acme.CertificateRequest {
	subject := parseOrCreateSubject()
	sans := parseOrCreateSANS()
	return acme.CertificateRequest{
		ChallengeType: acmeChallengeType,
		Valid:         365,
		KeyAttributes: parseOrCreateOrderKeyAttributes(),
		SANS:          &sans,
		Subject:       subject,
	}
}

func parseOrCreateOrderKeyAttributes() *keystore.KeyAttributes {
	// if acmeOrderKID != "" {
	// 	storeType, id, err := keystore.ParseKeyID(acmeOrderKID)
	// 	if err != nil {
	// 		log.Fatalf("Failed to parse key ID: %v", err)
	// 	}
	// 	fmt.Println(storeType)
	// 	fmt.Println(id)
	// }
	// return App.ServerKeyAttributes

	// keyAttrs, err := App.TPM.IDevIDAttributes()
	// if err != nil {
	// 	log.Fatalf("Failed to get IDevID key attributes: %v", err)
	// }
	// return keyAttrs

	return App.ServerKeyAttributes
}

func parseOrCreateAccountKeyConfig() *keystore.KeyConfig {
	return &keystore.KeyConfig{
		Debug:              App.WebServiceConfig.Key.Debug,
		ECCConfig:          App.WebServiceConfig.Key.ECCConfig,
		CN:                 App.WebServiceConfig.Key.CN,
		Hash:               App.WebServiceConfig.Key.Hash,
		KeyAlgorithm:       App.WebServiceConfig.Key.KeyAlgorithm,
		Password:           App.WebServiceConfig.Key.Password,
		PlatformPolicy:     App.WebServiceConfig.Key.PlatformPolicy,
		RSAConfig:          App.WebServiceConfig.Key.RSAConfig,
		SignatureAlgorithm: App.WebServiceConfig.Key.SignatureAlgorithm,
		StoreType:          keystore.STORE_TPM2.String(),
	}
}

// Returns a certificate SANS configuration using the parsed CLI options if provided,
// otherwise returns the web servers SANS configuration as defined by the platform
// configuration file
func parseOrCreateSANS() ca.SubjectAlternativeNames {
	if acmeSANSDNS != nil && acmeSANSEmails != nil && acmeSANSIPs != nil {
		return ca.SubjectAlternativeNames{
			DNS:   acmeSANSDNS,
			Email: acmeSANSEmails,
			IPs:   acmeSANSIPs,
		}
	}
	return *App.WebServiceConfig.Certificate.SANS
}

// Returns a subject using the parsed CLI options if provided, otherwise
// returns the web servers subject as defined by the platform configuration file
func parseOrCreateSubject() ca.Subject {

	if acmeSubjectCN != "" {
		required := map[string]string{
			"cn":                  acmeSubjectCN,
			"organization":        acmeSubjectOrganization,
			"organizational-unit": acmeSubjectOrganizationalUnit,
			"country":             acmeSubjectCountry,
			"province":            acmeSubjectProvince,
			"locality":            acmeSubjectLocality,
			"street-address":      acmeSubjectStreetAddress,
			"postal-code":         acmeSubjectPostalCode,
		}
		for name, field := range required {
			if field == "" {
				log.Fatalf("Missing required subject field: %s", name)
			}
		}
		return ca.Subject{
			CommonName:         acmeSubjectCN,
			Organization:       acmeSubjectOrganization,
			OrganizationalUnit: acmeSubjectOrganizationalUnit,
			Country:            acmeSubjectCountry,
			Province:           acmeSubjectProvince,
			Locality:           acmeSubjectLocality,
			Address:            acmeSubjectStreetAddress,
			PostalCode:         acmeSubjectPostalCode,
		}
	}

	return App.WebServiceConfig.Certificate.Subject
}
