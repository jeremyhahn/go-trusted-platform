package ca

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display an x509 certificate",
	Long:  `Print x509 certificate details in human readable and PEM form`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		storeType, err := keystore.ParseStoreType(KeyStore)
		if err != nil {
			App.Logger.Fatal(err)
		}

		algo, err := keystore.ParseKeyAlgorithm(Algorithm)
		if err != nil {
			App.Logger.Fatal(err)
		}

		keyAttrs, err := keystore.Template(algo)
		if err != nil {
			App.Logger.Fatal(err)
		}
		keyAttrs.StoreType = storeType

		certificate, err := App.CA.Certificate(keyAttrs)
		if err != nil {
			App.Logger.Fatal(err)
		}

		pem, err := certstore.EncodePEM(certificate.Raw)
		if err != nil {
			App.Logger.Fatal(err)
		}

		certstore.PrintCertificate(certificate)
		fmt.Println(string(pem))
	},
}
