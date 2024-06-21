package cmd

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"
)

var (
	CAInstallCACert,
	CAUninstallCACert,
	CAList bool

	CAPublicKey,
	CAIssueCertificate,
	CASubjectFile,
	CASansDNS,
	CASansIPs,
	CASansEmails,
	CAShowCert,
	CARevokeCert,
	CAParseDER,
	CAParsePEM string
)

func init() {

	caCmd.PersistentFlags().StringVarP(&CAPublicKey, "public-key", "g", "ca", "Get an issued certificate from the CA using its common name. (ex: --get-cn mydomain.com)")
	caCmd.PersistentFlags().BoolVarP(&CAInstallCACert, "install-ca", "i", false, "Installs the CA certifiate to the operation system trust store")
	caCmd.PersistentFlags().BoolVarP(&CAUninstallCACert, "uninstall-ca", "u", false, "Uninstalls the CA certifiate from the operation system trust store")
	caCmd.PersistentFlags().StringVar(&CAIssueCertificate, "issue", "", "Issue a new certificate. (ex: --issue mydomain.com)")
	caCmd.PersistentFlags().StringVar(&CAShowCert, "show", "", "Shows a certificate using openssl x509 -text")
	caCmd.PersistentFlags().StringVar(&CARevokeCert, "revoke", "", "Revoke a certificate")
	caCmd.PersistentFlags().BoolVarP(&CAList, "list", "l", false, "Get an issued certificate from the CA using its common name. (ex: --get-cn mydomain.com)")
	caCmd.PersistentFlags().StringVarP(&CASubjectFile, "config", "c", "/etc/example/tls.yaml", "Path to TLS subject configuration file")
	caCmd.PersistentFlags().StringVar(&CASansDNS, "sans-dns", "", "Comma separated list of SANS DNS names (ex: domain1.com,domain2.com)")
	caCmd.PersistentFlags().StringVar(&CASansIPs, "sans-ips", "", "Comma separated list of SANS IP Addresses (ex: 1.2.3.4,5.6.7.8)")
	caCmd.PersistentFlags().StringVar(&CASansEmails, "sans-emails", "", "Comma separated list of SANS IP Email addresses (ex: me@domain1.com,me@domain2.com)")
	caCmd.PersistentFlags().StringVar(&CAParseDER, "der", "", "Parses a DER encoded certificate")
	caCmd.PersistentFlags().StringVar(&CAParsePEM, "pem", "", "Parses a PEM encoded certificate")

	rootCmd.AddCommand(caCmd)
}

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority",
	Long: `The Certificate Authority provides Private Key Infrastructure (PKI)
services to the platform. Create, install, issue, and revoke certificates
or secure web services, mTLS, encryption, and identity management.`,
	Run: func(cmd *cobra.Command, args []string) {

		if CAParsePEM != "" {
			bytes, err := os.ReadFile(CAParsePEM)
			if err != nil {
				App.Logger.Fatal(err)
			}
			cert, err := App.CA.DecodePEM(bytes)
			if err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Infof("%+v", cert)
		}

		if CAParseDER != "" {
			bytes, err := os.ReadFile(CAParseDER)
			if err != nil {
				App.Logger.Fatal(err)
			}
			cert, err := x509.ParseCertificate(bytes)
			if err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Infof("%+v", cert)
		}

		// --show cn
		if CAShowCert != "" {
			wd, err := os.Getwd()
			if err != nil {
				App.Logger.Fatal(err)
			}
			arg0 := "x509"
			arg1 := "-in"
			arg2 := fmt.Sprintf("%s/%s/%s.crt", wd, App.CertDir, CAShowCert)
			arg3 := "-text"
			cmd := exec.Command("openssl", arg0, arg1, arg2, arg3)
			stdout, err := cmd.Output()
			if err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Info(string(stdout))
			os.Exit(0)
		}

		// --revoke cn
		if CARevokeCert != "" {
			err := App.CA.Revoke(CARevokeCert)
			if err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Info("Successfully revoked certificate")
			os.Exit(0)
		}

		// --install-ca
		if CAInstallCACert {
			rootCA, intermediateCAs, err := ca.NewCA(App.Logger, App.CertDir, &App.CAConfig, nil)
			if err != nil {
				App.Logger.Fatal(err)
			}
			if err := rootCA.TrustStore().Install(App.CAConfig.Identity[0].Subject.CommonName); err != nil {
				App.Logger.Fatal(err)
			}
			for cn, intermediateCA := range intermediateCAs {
				if err := intermediateCA.TrustStore().Install(cn); err != nil {
					App.Logger.Fatal(err)
				}
			}
			App.Logger.Info("CA certificate successfully installed")
			os.Exit(0)
		}

		// --uninstal-ca
		if CAUninstallCACert {
			rootCA, intermediateCAs, err := ca.NewCA(App.Logger, App.CertDir, &App.CAConfig, nil)
			if err != nil {
				App.Logger.Fatal(err)
			}
			if err := rootCA.TrustStore().Uninstall(App.CAConfig.Identity[0].Subject.CommonName); err != nil {
				App.Logger.Fatal(err)
			}
			for cn, intermediateCA := range intermediateCAs {
				if err := intermediateCA.TrustStore().Uninstall(cn); err != nil {
					App.Logger.Fatal(err)
				}
			}
			App.Logger.Info("CA certificate successfully uninstalled")
			os.Exit(0)
		}

		// --list
		if CAList {
			certs, err := App.CA.IssuedCertificates()
			if err != nil {
				App.Logger.Fatal(err)
			}
			for _, cert := range certs {
				App.Logger.Info(cert)
			}
			os.Exit(0)
		}

		// --issue
		if CAIssueCertificate != "" {

			var subject ca.Subject
			yamlFile, err := os.ReadFile(CASubjectFile)
			if err != nil {
				App.Logger.Fatal(err)
			}

			App.Logger.Info(string(yamlFile))

			err = yaml.Unmarshal(yamlFile, &subject)
			if err != nil {
				App.Logger.Fatal(err)
			}

			subject.CommonName = CAIssueCertificate

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

			request := ca.CertificateRequest{
				Valid:   365, // days
				Subject: subject,
				SANS: &ca.SubjectAlternativeNames{
					DNS:   dnsNames,
					IPs:   ips,
					Email: emails}}

			// Hard coding random number generator for now
			_, err = App.CA.IssueCertificate(request, rand.Reader)
			if err != nil {
				App.Logger.Error(err)
			}

			cert, err := App.CA.PEM(CAIssueCertificate)
			if err != nil {
				App.Logger.Error(err)
			}

			App.Logger.Info(string(cert))
			os.Exit(0)
		}

		// --public-key
		// This has a default value of nothing so it will always be true
		if CAPublicKey != "" {
			bytes, err := App.CA.PEM(CAPublicKey)
			if err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Info(string(bytes))
			os.Exit(0)
		}

	},
}
