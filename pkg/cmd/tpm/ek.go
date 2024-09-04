package tpm

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	bCertificate,
	bRSA,
	bECC bool
)

func init() {

	EKCmd.PersistentFlags().BoolVar(&bRSA, "rsa", false, "Retrieve the TPM 2.0 RSA Endorsement Key")
	EKCmd.PersistentFlags().BoolVar(&bECC, "ecc", false, "Retrieve the TPM 2.0 ECC ENdorsement Key")
	EKCmd.PersistentFlags().BoolVar(&bCertificate, "cert", true, "Retrieve the TPM 2.0 ENdorsement Key Certificate")
}

var EKCmd = &cobra.Command{
	Use:   "ek",
	Short: "Retrieve TPM 2.0 Public Endorsement Key",
	Long:  `Display TPM 2.0 Endorsement Public Key in PEM form`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		if err := App.OpenTPM(); err != nil {
			App.Logger.Warning(err)
		}
		defer func() {
			if err := App.TPM.Close(); err != nil {
				App.Logger.Fatal(err)
			}
		}()

		if !bRSA && !bRSA {
			fmt.Println("No algorithm flags, defaulting to RSA...")
			bRSA = true
		}

		if bRSA {
			rsaPub := App.TPM.EKRSA()
			fmt.Println(keystore.EncodePubKey(rsaPub))
		}

		if bECC {
			eccPub := App.TPM.EKECC()
			fmt.Println(keystore.EncodePubKey(eccPub))
		}

		if bCertificate {
			cert, err := App.TPM.EKCertificate()
			if err != nil {
				App.Logger.Fatal(err)
			}
			fmt.Println(certstore.EncodePEM(cert.Raw))
		}
	},
}
