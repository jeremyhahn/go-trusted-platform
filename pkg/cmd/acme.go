package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	acmeAuthzType    string
	acmeDirectoryURL string
	acmeCACert       string
	acmeAccountEmail string

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

	// Global client flags
	acmeCmd.PersistentFlags().StringVar(&acmeAuthzType, "authz-type", acme.AuthzTypePermanentIdentifier.String(), "The ACME authorization type (dns, ip, permanent-identifier)")
	acmeCmd.PersistentFlags().StringVar(&acmeCACert, "ca-cert", "ca-bundle.pem", "The ACME server root certificate")
	acmeCmd.PersistentFlags().StringVar(&acmeDirectoryURL, "directory", "https://localhost:8443/api/v1/acme/directory", "The ACME server directory URL")

	// // Account and Order Key ID flags
	// acmeCmd.PersistentFlags().StringVar(&acmeAccountKID, "account-kid", keystore.STORE_TPM2.String(), "The Key Store Module used for the ACME account private key")
	// acmeCmd.PersistentFlags().StringVar(&acmeOrderKID, "order-kid", keystore.STORE_TPM2.String(), "The Key Store Module used to place a new ACME order")

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

	rootCmd.AddCommand(acmeCmd)
}

var acmeCmd = &cobra.Command{
	Use:   "acme [action]",
	Short: "ACME certificate management",
	Long: `Performs x509 certificate management operations using the Automated
Certificate Management Environment (ACME) protocol`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {

		action := args[0]

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			log.Fatalf("Failed to load system root CAs: %v", err)
		}

		if acmeCACert != "" {
			cacert, err := os.ReadFile(acmeCACert)
			if err != nil {
				cmd.PrintErrln("Failed to read CA certificate")
			}
			if ok := rootCAs.AppendCertsFromPEM(cacert); !ok {
				cmd.PrintErrln("Failed to append CA certificate to the cert pool")
			}
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}

		httpClient := &http.Client{
			Transport: transport,
		}

		// Default the account key to the IDevID key if not provided
		if App.ACMEConfig == nil {
			if acmeAccountEmail == "" {
				cmd.PrintErrln("Missing required account email")
				return
			}
			App.ACMEConfig = &acme.Config{
				Client: &acme.ClientConfig{
					DirectoryURL: acmeDirectoryURL,
					Account: &acme.AccountConfig{
						Email: acmeAccountEmail,
						Key:   parseOrCreateAccountKeyConfig(),
					},
				},
			}
		}

		daoFactory, err := kvstore.New(
			App.Logger,
			App.DatastoreConfig,
		)
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		client, err := acme.NewClient(
			*App.ACMEConfig.Client, httpClient, App.CA, daoFactory, App.TPM)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		switch action {

		// case "download":
		// _, err := client.DownloadCertificate()
		// if err != nil {
		// 	cmd.PrintErrln(err)
		// 	return
		// }

		case "enroll":
			authzType, err := acme.ParseAuthzType(acmeAuthzType)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			account, err := client.RegisterAccount()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cert, err := client.RequestCertificate(account, authzType, certificateRequest())
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

			fmt.Println(certstore.ToString(cert))

		case "register":
			_, err := client.RegisterAccount()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

		default:
			cmd.PrintErrln("Invalid command")
			return

		}

	},
}

func certificateRequest() ca.CertificateRequest {
	subject := parseOrCreateSubject()
	sans := parseOrCreateSANS()
	return ca.CertificateRequest{
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

	keyAttrs, err := App.TPM.IDevIDAttributes()
	if err != nil {
		log.Fatalf("Failed to get IDevID key attributes: %v", err)
	}
	return keyAttrs
}

func parseOrCreateAccountKeyConfig() *keystore.KeyConfig {
	return &keystore.KeyConfig{
		Debug:              App.TPMConfig.IDevID.Debug,
		ECCConfig:          App.TPMConfig.IDevID.ECCConfig,
		CN:                 App.TPMConfig.IDevID.CN,
		Hash:               App.TPMConfig.IDevID.Hash,
		KeyAlgorithm:       App.TPMConfig.IDevID.KeyAlgorithm,
		Password:           App.TPMConfig.IDevID.Password,
		PlatformPolicy:     App.TPMConfig.IDevID.PlatformPolicy,
		RSAConfig:          App.TPMConfig.IDevID.RSAConfig,
		SignatureAlgorithm: App.TPMConfig.IDevID.SignatureAlgorithm,
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
	return *App.WebService.Certificate.SANS
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

	return App.WebService.Certificate.Subject
}
