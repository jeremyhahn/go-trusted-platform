package platform

import (
	"crypto/x509"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	krCA             bool
	krHMAC           bool
	krParentHandle   uint32
	krParentPassword string
	krParentPolicy   bool
	krPassword       string
	krPolicy         bool
	krTLS            bool
)

func init() {

	// Options
	KeyringCmd.PersistentFlags().Uint32VarP(&krParentHandle, "parent", "p", 0x81000002, "Parent handle to seal against. Defaults to the Shared SRK")
	KeyringCmd.PersistentFlags().StringVar(&krParentPassword, "parent-password", "", "The parent key authorization password")
	KeyringCmd.PersistentFlags().BoolVar(&krParentPolicy, "parent-policy", true, "True to use the platform PCR session as the parent key authorization value")
	KeyringCmd.PersistentFlags().StringVar(&krPassword, "password", "", "The seal keyed hash password")

	// Flags
	KeyringCmd.PersistentFlags().BoolVar(&krCA, "ca", false, "Key type: CA")
	KeyringCmd.PersistentFlags().BoolVar(&krHMAC, "hmac", false, "Key type: HMAC")
	KeyringCmd.PersistentFlags().BoolVar(&krTLS, "tls", false, "Key type: TLS")
	KeyringCmd.PersistentFlags().BoolVar(&krPolicy, "policy", true, "True to attach the platform policy digest to the keyed hash object")
}

var KeyringCmd = &cobra.Command{
	Use:   "keyring [action] [cn] [store] [algorithm]",
	Short: "Keyring operations",
	Long:  `Perform keyring operations`,
	Args:  cobra.MinimumNArgs(3),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 4 {
			cmd.Help()
			os.Exit(0)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		action := args[0]
		cn := args[1]
		store := args[2]
		algorithm := args[3]

		storeType, err := keystore.ParseStoreType(store)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		keyAlg, err := keystore.ParseKeyAlgorithm(algorithm)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		var keyType keystore.KeyType
		if krCA {
			keyType = keystore.KEY_TYPE_CA
		}
		if krTLS {
			keyType = keystore.KEY_TYPE_TLS
		}
		if krHMAC || !krCA && !krTLS && !krHMAC {
			keyType = keystore.KEY_TYPE_HMAC
		}

		parentHandle := tpm2.TPMHandle(krParentHandle)
		parentAttrs, err := App.TPM.KeyAttributes(parentHandle)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		if InitParams.SOPin != nil {
			parentAttrs.TPMAttributes.HierarchyAuth = keystore.NewClearPassword([]byte(InitParams.SOPin))
		}
		if krParentPassword != "" {
			parentAttrs.Password = keystore.NewClearPassword([]byte(krParentPassword))
		}
		parentAttrs.PlatformPolicy = krParentPolicy

		keyAttrs := &keystore.KeyAttributes{
			CN:             cn,
			StoreType:      storeType,
			KeyAlgorithm:   keyAlg,
			KeyType:        keyType,
			Parent:         parentAttrs,
			PlatformPolicy: krParentPolicy,
		}
		if krPassword != "" {
			keyAttrs.Password = keystore.NewClearPassword([]byte(krPassword))
		}

		switch action {

		case "generate":
			opaqueKey, err := App.PlatformKS.GenerateKey(keyAttrs)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			der, err := x509.MarshalPKIXPublicKey(opaqueKey.Public())
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := keystore.EncodePEM(der)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))

		case "delete":
			err := App.PlatformKS.Delete(keyAttrs)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

		default:
			opaqueKey, err := App.PlatformKS.Key(keyAttrs)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			der, err := x509.MarshalPKIXPublicKey(opaqueKey.Public())
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			pem, err := keystore.EncodePEM(der)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(string(pem))
		}

	},
}
