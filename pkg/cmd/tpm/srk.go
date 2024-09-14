package tpm

import (
	"crypto/x509"
	"fmt"

	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	srkCA             bool
	srkCN             string
	srkECDSA          bool
	srkHandle         uint32
	srkMAC            bool
	srkParentHandle   uint32
	srkParentPassword string
	srkParentPolicy   bool
	srkPassword       string
	srkPersistent     bool
	srkPolicy         bool
	srkRSA            bool
	srkTLS            bool
)

func init() {

	// Options
	SRKCmd.PersistentFlags().Uint32Var(&srkParentHandle, "ek", 0x81010001, "EK handle used to salt and encrypt the session")
	SRKCmd.PersistentFlags().StringVar(&srkParentPassword, "ek-password", "", "EK authorization password")

	SRKCmd.PersistentFlags().StringVar(&srkCN, "cn", "", "The common name for the key")
	SRKCmd.PersistentFlags().Uint32Var(&srkHandle, "handle", 0x81000001, "Parent handle to seal against. Defaults to the Shared SRK")

	// Flags
	SRKCmd.PersistentFlags().BoolVar(&srkECDSA, "ecdsa", false, "ECC Storage Root Key")
	SRKCmd.PersistentFlags().BoolVar(&srkRSA, "rsa", false, "RSA Storage Root Key")
	SRKCmd.PersistentFlags().StringVar(&srkPassword, "password", "", "The seal keyed hash password")
	SRKCmd.PersistentFlags().BoolVar(&srkPersistent, "persistent", true, "Persistent handle flag")
	SRKCmd.PersistentFlags().BoolVar(&srkPolicy, "policy", true, "True to attach the platform policy digest to the keyed hash object")
}

var SRKCmd = &cobra.Command{
	Use:   "srk [action]",
	Short: "TPM 2.0 Storage Root Key Operations",
	Long:  `Perform operations on a TPM 2.0 Storage Root Key`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		soPIN := keystore.NewClearPassword(InitParams.SOPin)

		keyAlg := x509.RSA
		template := tpm2.RSASRKTemplate

		if srkECDSA {
			keyAlg = x509.ECDSA
			template = tpm2.ECCSRKTemplate
		}

		if !srkRSA && !srkECDSA {
			fmt.Println("No algorithm flags, defaulting to RSA...")
		}

		// Set the handle type
		handleType := tpm2.TPMHTTransient
		if srkPersistent {
			handleType = tpm2.TPMHTPersistent
		}

		// Set SRK password
		var passwd keystore.Password
		if len(srkPassword) > 0 {
			passwd = keystore.NewClearPassword([]byte(srkPassword))
		}

		// Get the EK attributes (used to encrypt and salt the session)
		ekAttrs, err := App.TPM.KeyAttributes(tpm2.TPMHandle(srkParentHandle))
		if err != nil {
			color.New(color.FgRed).Println(err)
			return
		}
		ekAttrs.KeyType = keystore.KEY_TYPE_ENDORSEMENT
		ekAttrs.Password = keystore.NewClearPassword([]byte(srkParentPassword))

		// Create SRK key attributes. Use EK (set as the parent)
		// to create salted, encrypted connection to the TPM
		keyAttrs := &keystore.KeyAttributes{
			CN:             srkCN,
			KeyAlgorithm:   keyAlg,
			KeyType:        keystore.KEY_TYPE_STORAGE,
			Parent:         ekAttrs,
			Password:       passwd,
			PlatformPolicy: srkPolicy,
			StoreType:      keystore.STORE_TPM2,
			TPMAttributes: &keystore.TPMAttributes{
				Handle:        tpm2.TPMHandle(srkHandle),
				HandleType:    handleType,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: soPIN,
				Template:      template,
			},
		}

		// No args, display the SRK public key in PEM form
		if len(args) == 0 {
			persistedKeyAttrs, err := App.TPM.KeyAttributes(tpm2.TPMHandle(srkHandle))
			if err != nil {
				color.New(color.FgRed).Println(err)
				return
			}
			keyAttrs.TPMAttributes = persistedKeyAttrs.TPMAttributes
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

		case "create-key":
			err := App.TPM.CreateSRK(keyAttrs)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := keystore.EncodePEM(keyAttrs.TPMAttributes.PublicKeyBytes)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))

		case "delete-key":
			name, _, err := App.TPM.ReadHandle(tpm2.TPMHandle(srkHandle))
			keyAttrs.KeyType = keystore.KEY_TYPE_STORAGE
			keyAttrs.TPMAttributes.Name = name
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			if err := App.TPM.DeleteKey(keyAttrs, nil); err != nil {
				cmd.PrintErrln(err)
				return
			}

		default:
			cmd.Help()
			return
		}
	},
}
