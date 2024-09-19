package ca

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	certPEM bool
)

func init() {
	CertificateCmd.PersistentFlags().BoolVar(&certPEM, "pem", false, "Display the x509 certificate in PEM form")
}

var CertificateCmd = &cobra.Command{
	Use:   "certificate [cn] [store] [algorithm]",
	Short: "x509 certificate operations",
	Long:  `Perform x509 certificate operations`,
	Args:  cobra.MinimumNArgs(3),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 3 {
			cmd.Help()
			return nil
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

		cn := args[0]
		storeType := args[1]
		algorithm := args[2]

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		userPIN := keystore.NewClearPassword(InitParams.Pin)
		if err := App.LoadCA(userPIN); err != nil {
			cmd.PrintErrln(err)
			return
		}

		parsedStoreType, err := keystore.ParseStoreType(storeType)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		algo, err := keystore.ParseKeyAlgorithm(algorithm)
		if err != nil {
			cmd.Println(err)
			return
		}

		keyAttrs, err := keystore.Template(algo)
		if err != nil {
			cmd.Println(err)
			return
		}
		keyAttrs.CN = cn
		keyAttrs.StoreType = parsedStoreType

		certificate, err := App.CA.Certificate(keyAttrs)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		if certPEM {
			pem, err := certstore.EncodePEM(certificate.Raw)
			if err != nil {
				cmd.Println(err)
				return
			}
			cmd.Printf(string(pem))
			return
		}

		prompt.PrintBanner(app.Version)

		cmd.Println(certstore.ToString(certificate))
	},
}
