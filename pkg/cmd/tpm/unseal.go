package tpm

import (
	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {

	UnsealCmd.PersistentFlags().Uint32VarP(&slParentHandle, "parent", "p", 0x81000002, "Parent handle to seal against. Defaults to the Shared SRK")
	UnsealCmd.PersistentFlags().StringVar(&slParentPassword, "parent-password", "", "The parent key authorization password")
	UnsealCmd.PersistentFlags().BoolVar(&slParentPolicy, "parent-policy", true, "True to use the platform PCR session as the parent key authorization value")

	UnsealCmd.PersistentFlags().StringVar(&slPassword, "password", "", "The seal keyed hash password")
	UnsealCmd.PersistentFlags().BoolVar(&slPolicy, "policy", true, "True to attach the platform policy digest to the keyed hash object")
}

var UnsealCmd = &cobra.Command{
	Use:   "unseal [cn]",
	Short: "Unseal a secret sealed to the TPM",
	Long:  `Unseal a secret sealed to a TPM keyed hash object`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cn := args[0]

		var passwd, parentPasswd keystore.Password
		if len(slParentPassword) > 0 {
			parentPasswd = keystore.NewClearPassword([]byte(slParentPassword))
		}
		if len(slPassword) > 0 {
			passwd = keystore.NewClearPassword([]byte(slPassword))
		}

		srkAttrs := App.PlatformKS.SRKAttributes()
		if parentPasswd != nil {
			srkAttrs.Password = parentPasswd
		}
		srkAttrs.PlatformPolicy = slParentPolicy
		srkAttrs.TPMAttributes.HierarchyAuth = keystore.NewClearPassword(InitParams.SOPin)

		keyAttrs, _ := keystore.Template(x509.RSA)
		keyAttrs.CN = cn
		keyAttrs.KeyAlgorithm = x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash)
		keyAttrs.KeyType = keystore.KEY_TYPE_HMAC
		keyAttrs.Parent = srkAttrs
		keyAttrs.Password = passwd
		keyAttrs.PlatformPolicy = slPolicy
		keyAttrs.StoreType = keystore.STORE_TPM2

		secret, err := App.TPM.Unseal(keyAttrs, nil)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Println(string(secret))
	},
}
