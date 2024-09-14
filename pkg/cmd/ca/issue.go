package ca

import (
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {
	// IssueCmd.PersistentFlags().StringVar(&CN, "cn", "", "The common name for the certificate. Ex: --cn example.com")
	// IssueCmd.PersistentFlags().StringVarP(&KeyStore, "store", "s", "tpm2", "Key store type [ pkcs8 | pkcs11 | tpm2 ]")
	// IssueCmd.PersistentFlags().StringVarP(&Algorithm, "algorithm", "a", "ecdsa", "The key algorithm [ rsa | ecdsa | ed25519 ]")
}

var IssueCmd = &cobra.Command{
	Use:   "issue [cn] [store] [algorithm]",
	Short: "Issues a new x509 Certificate",
	Long:  `Issue a new x509 certificate from the Certificate Authority.`,
	Run: func(cmd *cobra.Command, args []string) {

		var subject ca.Subject

		App.Init(InitParams)

		cn := args[0]
		store := args[1]
		algorithm := args[2]

		dnsNames := []string{}
		ips := []string{}
		emails := []string{}

		if SansDNS != "" {
			dnsNames = strings.Split(SansDNS, ",")
		}
		if SansIPs != "" {
			ips = strings.Split(SansIPs, ",")
		}
		if SansEmails != "" {
			emails = strings.Split(SansEmails, ",")
		}

		storeType, err := keystore.ParseStoreType(store)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		keyAlgo, err := keystore.ParseKeyAlgorithm(algorithm)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		attrs, err := keystore.Template(keyAlgo)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		attrs.CN = cn
		attrs.KeyAlgorithm = keyAlgo
		attrs.KeyType = keystore.KEY_TYPE_TLS
		attrs.StoreType = storeType

		subject.CommonName = cn

		request := ca.CertificateRequest{
			KeyAttributes: attrs,
			Valid:         365, // days
			Subject:       subject,
			SANS: &ca.SubjectAlternativeNames{
				DNS:   dnsNames,
				IPs:   ips,
				Email: emails}}

		if _, err = App.CA.IssueCertificate(request); err != nil {
			cmd.PrintErrln(err)
			return
		}

		cert, err := App.CA.PEM(attrs)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Println(string(cert))
	},
}
