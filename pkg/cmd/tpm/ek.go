package tpm

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	ekCA             bool
	ekCert           bool
	ekCN             string
	ekECC            bool
	ekHandle         uint32
	ekMAC            bool
	ekParentHandle   uint32
	ekParentPassword string
	ekParentPolicy   bool
	ekPassword       string
	ekPersistent     bool
	ekPolicy         bool
	ekRSA            bool
	ekTLS            bool
)

func init() {

	// Options
	EKCmd.PersistentFlags().Uint32Var(&ekHandle, "handle", 0x81010001, "Defaults to the TCG recommended EK index")
	EKCmd.PersistentFlags().StringVar(&ekCN, "cn", "", "The EK common name")

	// Flags
	EKCmd.PersistentFlags().BoolVar(&ekRSA, "rsa", false, "RSA Endorsement Key")
	EKCmd.PersistentFlags().BoolVar(&ekECC, "ecdsa", false, "ECC Endorsement Key")
	EKCmd.PersistentFlags().BoolVar(&ekCert, "cert", true, "Endorsement Key Certificate")
	EKCmd.PersistentFlags().StringVar(&ekPassword, "password", "", "The key authorization password")
	EKCmd.PersistentFlags().BoolVar(&ekPersistent, "persistent", true, "Persistent handle flag")
	EKCmd.PersistentFlags().BoolVar(&ekPolicy, "policy", false, "True to save the password as a keyed hash with platform PCR policy authorization")
}

var EKCmd = &cobra.Command{
	Use:   "ek [action]",
	Short: "TPM 2.0 Endorsement Key Operations",
	Long:  `Perform operations on a TPM 2.0 Endorsement Key`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		soPIN := keystore.NewClearPassword(InitParams.SOPin)

		keyAlg := x509.RSA
		template := tpm2.RSASRKTemplate

		if ekECC {
			keyAlg = x509.ECDSA
			template = tpm2.ECCSRKTemplate
		}

		if !ekRSA && !ekECC {
			fmt.Println("No algorithm flags, defaulting to RSA...")
		}

		handleType := tpm2.TPMHTTransient
		if ekPersistent {
			handleType = tpm2.TPMHTPersistent
		}

		var passwd keystore.Password
		if len(ekPassword) > 0 {
			passwd = keystore.NewClearPassword([]byte(ekPassword))
		}

		ekAttrs := &keystore.KeyAttributes{
			CN:             ekCN,
			Password:       passwd,
			KeyAlgorithm:   keyAlg,
			KeyType:        keystore.KEY_TYPE_ENDORSEMENT,
			PlatformPolicy: ekPolicy,
			TPMAttributes: &keystore.TPMAttributes{
				Handle:        tpm2.TPMHandle(ekHandle),
				HandleType:    handleType,
				Hierarchy:     tpm2.TPMRHEndorsement,
				HierarchyAuth: soPIN,
				Template:      template,
			},
		}

		// No args, display the EK public key in PEM form
		if len(args) == 0 {
			keyAttrs, err := App.TPM.KeyAttributes(tpm2.TPMHandle(ekHandle))
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			keyAttrs.TPMAttributes.HandleType = tpm2.TPMHTPersistent
			cmd.Println(keyAttrs)

			pem, err := keystore.EncodePEM(keyAttrs.TPMAttributes.PublicKeyBytes)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))
			return
		}

		switch args[0] {

		case "certificate":
			cert, err := App.TPM.EKCertificate()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := certstore.EncodePEM(cert.Raw)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))

		case "create-key":
			err := App.TPM.CreateEK(ekAttrs)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := keystore.EncodePEM(ekAttrs.TPMAttributes.PublicKeyBytes)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))

		case "delete-key":
			prompt.PrintBanner(app.Version)
			name, _, err := App.TPM.ReadHandle(tpm2.TPMHandle(ekHandle))
			ekAttrs.TPMAttributes.Name = name
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			if err := App.TPM.DeleteKey(ekAttrs, nil); err != nil {
				cmd.PrintErrln(err)
				return
			}

		case "import-certificate":
			cert, err := App.ImportEndorsementKeyCertificate()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := certstore.EncodePEM(cert.Raw)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))

		default:
			cmd.Help()
			return
		}

	},
}
