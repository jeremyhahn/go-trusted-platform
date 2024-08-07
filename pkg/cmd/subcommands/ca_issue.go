package subcommands

import (
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func init() {
	CAIssueCmd.PersistentFlags().StringVar(&CACertCN, "cn", "", "The common name for the certificate. Ex: --cn example.com")
	CAIssueCmd.PersistentFlags().StringVarP(&CAFile, "config", "c", "/etc/example/tls.yaml", "Path to PKIX subject configuration file")
}

var CAIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issues a new x509 Certificate",
	Long:  `Issue a new x509 certificate from the Certificate Authority.`,
	Run: func(cmd *cobra.Command, args []string) {
		var subject ca.Subject

		yamlFile, err := os.ReadFile(CAFile)
		if err != nil {
			App.Logger.Fatal(err)
		}

		App.Logger.Info(string(yamlFile))

		err = yaml.Unmarshal(yamlFile, &subject)
		if err != nil {
			App.Logger.Fatal(err)
		}

		subject.CommonName = CACertCN

		dnsNames := []string{}
		ips := []string{}
		emails := []string{}

		if CASansDNS != "" {
			dnsNames = strings.Split(CASansDNS, ",")
		}
		if CASansIPs != "" {
			ips = strings.Split(CASansIPs, ",")
		}
		if CASansEmails != "" {
			emails = strings.Split(CASansEmails, ",")
		}

		caAttrs := App.CA.CAKeyAttributes(nil)
		attrs, err := keystore.Template(caAttrs.KeyAlgorithm)
		attrs.KeyType = keystore.KEY_TYPE_TLS
		attrs.Domain = "example.com"
		attrs.CN = "www.example.com"
		attrs.AuthPassword = []byte(InitParams.CAPassword)
		attrs.Password = []byte(InitParams.ServerPassword)

		request := ca.CertificateRequest{
			KeyAttributes: &attrs,
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

		cert, err := App.CA.PEM(caAttrs)
		if err != nil {
			App.Logger.Error(err)
		}

		App.Logger.Info(string(cert))
	},
}
