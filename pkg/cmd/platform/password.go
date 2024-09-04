package platform

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	authValue,
	algorithm,
	cn,
	storeType string
	policy bool
)

func init() {

	PasswordCmd.PersistentFlags().StringVar(&cn, "cn", "", "The key attributes common name")
	PasswordCmd.PersistentFlags().StringVar(&storeType, "store", "pkcs8", "The key store type [ pkcs8 | pkcs11 | tpm2 ]")
	PasswordCmd.PersistentFlags().StringVar(&algorithm, "algorithm", "rsa", "The key algorithm [ rsa | ecdsa | ed25119 ]")
	PasswordCmd.PersistentFlags().StringVar(&authValue, "auth", "", "The parent key authorization password")
	PasswordCmd.PersistentFlags().BoolVar(&policy, "policy", false, "Use the platform PCR policy as an authorization value")
}

var PasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Retrieves a sealed password",
	Long:  `Performs a TPM password unseal operation on the requested key.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		if err := App.OpenTPM(); err != nil {
			App.Logger.Fatal(err)
		}

		store, err := keystore.ParseStoreType(storeType)
		if err != nil {
			App.Logger.Fatal(err)
		}

		keyAlg, err := keystore.ParseKeyAlgorithm(algorithm)
		if err != nil {
			App.Logger.Fatal(err)
		}

		srkAttrs := App.PlatformKS.SRKAttributes()

		if authValue != "" {
			srkAttrs.Password = keystore.NewClearPassword([]byte(authValue))
		}

		keyAttrs := &keystore.KeyAttributes{
			CN:             cn,
			KeyAlgorithm:   keyAlg,
			Parent:         srkAttrs,
			PlatformPolicy: policy,
			KeyType:        keystore.KEY_TYPE_HMAC,
			StoreType:      store,
		}
		password, err := App.TPM.Unseal(keyAttrs, nil)
		if err != nil {
			App.Logger.Fatal(err)
		}

		fmt.Println(string(password))
	},
}
