package tpm

import (
	"bufio"
	"crypto/x509"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	slParentHandle   uint32
	slParentPassword string
	slParentPolicy   bool
	slPassword       string
	slPolicy         bool
)

func init() {

	SealCmd.PersistentFlags().Uint32VarP(&slParentHandle, "parent", "p", 0x81000002, "Parent handle to seal against. Defaults to the Shared SRK")
	SealCmd.PersistentFlags().StringVar(&slParentPassword, "parent-password", "", "The parent key authorization password")
	SealCmd.PersistentFlags().BoolVar(&slParentPolicy, "parent-policy", true, "True to use the platform PCR session as the parent key authorization value")

	SealCmd.PersistentFlags().StringVar(&slPassword, "password", "", "The seal keyed hash password")
	SealCmd.PersistentFlags().BoolVar(&slPolicy, "policy", true, "True to attach the platform policy digest to the keyed hash object")
}

var SealCmd = &cobra.Command{
	Use:   "seal [cn] [secret]",
	Short: "Seal a secret to the TPM",
	Long:  `Seals a secret to a TPM keyed hash object`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cn := args[0]

		var secret []byte
		var size int64
		stdin := os.Stdin
		fi, err := stdin.Stat()
		if err == nil {
			goto SEAL
		}
		size = fi.Size()
		if size > 0 {
			reader := bufio.NewReader(os.Stdin)
			text, err := reader.ReadString('\n')
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			secret = []byte(strings.TrimSpace(text))
		}

	SEAL:

		if len(args) > 1 {
			secret = []byte(args[1])
		}

		var passwd, parentPasswd keystore.Password
		if len(slParentPassword) > 0 {
			parentPasswd = keystore.NewClearPassword([]byte(slParentPassword))
		}
		if len(slPassword) > 0 {
			passwd = keystore.NewClearPassword([]byte(slPassword))
		}

		keyAttrs, _ := keystore.Template(x509.RSA)
		keyAttrs.CN = cn
		keyAttrs.KeyAlgorithm = x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash)
		keyAttrs.KeyType = keystore.KEY_TYPE_HMAC
		keyAttrs.Password = passwd
		keyAttrs.Parent = &keystore.KeyAttributes{
			Password:       parentPasswd,
			PlatformPolicy: slParentPolicy,
			TPMAttributes: &keystore.TPMAttributes{
				Handle:        tpm2.TPMHandle(slParentHandle),
				HandleType:    tpm2.TPMHTTransient,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: keystore.NewClearPassword(InitParams.SOPin),
			},
		}
		keyAttrs.PlatformPolicy = slPolicy
		keyAttrs.Secret = keystore.NewClearPassword(secret)
		keyAttrs.StoreType = keystore.STORE_TPM2

		if _, err := App.TPM.Seal(keyAttrs, nil); err != nil {
			cmd.PrintErrln(err)
		}
	},
}
