package ca

import (
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {
	IssueCmd.PersistentFlags().StringVar(&CN, "cn", "", "The common name for the certificate. Ex: --cn example.com")
	IssueCmd.PersistentFlags().StringVarP(&KeyStore, "store", "s", "tpm2", "Key store type [ pkcs8 | pkcs11 | tpm2 ]")
	IssueCmd.PersistentFlags().StringVarP(&Algorithm, "algorithm", "a", "ecdsa", "The key algorithm [ rsa | ecdsa | ed25519 ]")
}

var IssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issues a new x509 Certificate",
	Long:  `Issue a new x509 certificate from the Certificate Authority.`,
	Run: func(cmd *cobra.Command, args []string) {

		var subject ca.Subject

		App.Init(InitParams)

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

		storeType, err := keystore.ParseStoreType(KeyStore)
		if err != nil {
			App.Logger.Fatal(err)
		}
		keyAlgo, err := keystore.ParseKeyAlgorithm(Algorithm)
		if err != nil {
			App.Logger.Fatal(err)
		}

		fmt.Printf("Key common name: %s\n", CN)
		fmt.Printf("Key store: %s\n", KeyStore)
		fmt.Printf("Key algorithm: %s\n", Algorithm)

		attrs, err := keystore.Template(keyAlgo)
		if err != nil {
			App.Logger.Fatal(err)
		}

		attrs.CN = CN
		attrs.KeyAlgorithm = keyAlgo
		attrs.KeyType = keystore.KEY_TYPE_TLS
		attrs.StoreType = storeType

		subject.CommonName = CN

		request := ca.CertificateRequest{
			KeyAttributes: attrs,
			Valid:         365, // days
			Subject:       subject,
			SANS: &ca.SubjectAlternativeNames{
				DNS:   dnsNames,
				IPs:   ips,
				Email: emails}}

		_, err = App.CA.IssueCertificate(request)
		if err != nil {
			App.Logger.Error(err)
		}

		cert, err := App.CA.PEM(attrs)
		if err != nil {
			App.Logger.Error(err)
		}

		fmt.Println(string(cert))
	},
}
