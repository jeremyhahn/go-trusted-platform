package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/deviceattest01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

var (
	ErrAccountNotFound       = errors.New("ACME account not found")
	ErrRegistrationFailed    = errors.New("ACME registration failed")
	ErrOrderCreationFailed   = errors.New("ACME order creation failed")
	ErrChallengeResolution   = errors.New("ACME challenge resolution failed")
	ErrChallengeFinalization = errors.New("ACME challenge finalization failed")
	ErrAuthorizationFailed   = errors.New("ACME authorization failed")

	mailTo = "mailto:"
)

type ACMEClient struct {
	accountKeyAttrs *keystore.KeyAttributes
	ca              ca.CertificateAuthority
	client          *acme.Client
	config          ClientConfig
	daoFactory      datastore.Factory
	tpm             tpm2.TrustedPlatformModule
}

// Creates a new ACME client
func NewClient(
	config ClientConfig,
	client *http.Client,
	ca ca.CertificateAuthority,
	daoFactory datastore.Factory,
	tpm tpm2.TrustedPlatformModule) (*ACMEClient, error) {

	accountKeyAttrs, err := keystore.KeyAttributesFromConfig(config.Account.Key)
	if err != nil {
		return nil, err
	}
	store, err := ca.Keyring().Store(accountKeyAttrs.StoreType.String())
	if err != nil {
		return nil, err
	}
	signer, err := store.Signer(accountKeyAttrs)
	if err != nil {
		if err == keystore.ErrFileNotFound {
			signer, err = store.GenerateKey(accountKeyAttrs)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	acmeClient := &acme.Client{
		DirectoryURL: config.DirectoryURL,
		Key:          signer,
		HTTPClient:   client,
	}
	return &ACMEClient{
		accountKeyAttrs: accountKeyAttrs,
		ca:              ca,
		client:          acmeClient,
		config:          config,
		daoFactory:      daoFactory,
		tpm:             tpm,
	}, nil
}

// Returns the ACME account associated with the account email provided by the
// platform configuration file
func (ac *ACMEClient) Account() (*acme.Account, error) {
	if ac.config.Account == nil {
		return nil, ErrAccountNotFound
	}
	accountDAO, err := ac.daoFactory.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	account, err := accountDAO.Get(
		util.NewID([]byte(ac.config.Account.Email)), datastore.CONSISTENCY_LOCAL)
	if err != nil {
		return nil, err
	}
	return &acme.Account{
		OrdersURL: account.Orders,
		Status:    account.Status,
		Contact:   account.Contact,
	}, nil
}

// Returns the ACME account associated with the provided email address
func (ac *ACMEClient) AccountFromEmail(email string) (*acme.Account, error) {
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, email)},
	}
	accountDAO, err := ac.daoFactory.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	accountDAO.Save(&entities.ACMEAccount{
		Contact: account.Contact,
	})
	return nil, ErrAccountNotFound
}

// Registers a new account with the ACME server using the account email
// provided by the platform configuration file
func (ac *ACMEClient) RegisterAccount() (*acme.Account, error) {
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, ac.config.Account.Email)},
	}
	newAccount, err := ac.client.Register(context.Background(), account, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}
	accountDAO, err := ac.daoFactory.ACMEAccountDAO()
	if err != nil {
		return nil, err
	}
	accountDAO.Save(&entities.ACMEAccount{
		Contact: newAccount.Contact,
	})
	return newAccount, nil
}

// Registers a new account with the ACME server using the provided email address
func (ac *ACMEClient) RegisterAccountWithEmail(email string) (*acme.Account, error) {
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, email)},
	}
	newAccount, err := ac.client.Register(context.Background(), account, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}
	return newAccount, nil
}

// Creates a new Certificate Signing Request (CSR) and ACME order for the provided domain,
// retrieves the authorization URLs and challenges, resolves the ACME challenge, finalizes
// the order, and downloads the issued certificate.
func (ac *ACMEClient) RequestCertificate(
	account *acme.Account,
	authzType AuthzType,
	certRequest ca.CertificateRequest) (*x509.Certificate, error) {

	ekCert, err := ac.tpm.EKCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get EK certificate: %v", err)
	}

	var cert *x509.Certificate

	operation := func() error {

		order, err := ac.client.AuthorizeOrder(context.Background(), []acme.AuthzID{{
			Type:  authzType.String(),
			Value: ekCert.SerialNumber.String(),
		}})
		if err != nil {
			return fmt.Errorf("failed to authorize order: %v", err)
		}

		for _, authzURL := range order.AuthzURLs {

			authz, err := ac.client.GetAuthorization(context.Background(), authzURL)
			if err != nil {
				return fmt.Errorf("failed to get authorization: %v", err)
			}

			for _, challenge := range authz.Challenges {

				// _, err := ac.client.Accept(context.Background(), challenge)
				// if err != nil {
				// 	return fmt.Errorf("failed to accept challenge: %v", err)
				// }

				// // Call handler_order_finalize
				// authz, err = ac.client.WaitAuthorization(context.Background(), authz.URI)
				// if err != nil {
				// 	return fmt.Errorf("failed to wait for authorization: %v", err)
				// }

				// if authz.Status != acme.StatusValid {
				// 	return fmt.Errorf("authorization status is not valid: %v", authz.Status)
				// }

				switch challenge.Type {

				case AuthzTypePermanentIdentifier.String():

					fmt.Println("Performing device-attest-01 challenge")

					_, err := deviceattest01.GenerateStatement(
						challenge.Token, certRequest.KeyAttributes, deviceattest01.ATTESTATION_FORMAT_TPM, ac.tpm)
					if err != nil {
						return fmt.Errorf("failed to generate attestation statement: %v", err)
					}

					_, err = ac.client.Accept(context.Background(), challenge)
					if err != nil {
						return fmt.Errorf("failed to accept challenge: %v", err)
					}

					// Call handler_order_finalize
					authz, err = ac.client.WaitAuthorization(context.Background(), authz.URI)
					if err != nil {
						return fmt.Errorf("failed to wait for authorization: %v", err)
					}

					if authz.Status != acme.StatusValid {
						return fmt.Errorf("authorization status is not valid: %v", authz.Status)
					}
				}
			}
		}

		// ekCert, err := ac.tpm.EKCertificate()
		// if err != nil {
		// 	return fmt.Errorf("failed to get EK certificate: %v", err)
		// }

		var subject ca.Subject
		if ac.config.Subject == nil {
			subject = ac.ca.Identity().Subject
			subject.CommonName = certRequest.Subject.CommonName
		} else {
			subject = *ac.config.Subject
		}

		csrDER, err := ac.ca.CreateCSR(certRequest)
		if err != nil {
			return fmt.Errorf("failed to create CSR: %v", err)
		}

		orderCertChain, _, err := ac.client.CreateOrderCert(context.Background(), order.FinalizeURL, csrDER, true)
		if err != nil {
			return fmt.Errorf("failed to finalize order: %v", err)
		}

		cert, err = x509.ParseCertificate(orderCertChain[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		if cert.Subject.CommonName != subject.CommonName {
			return fmt.Errorf("certificate common name does not match domain: %s", cert.Subject.CommonName)
		}

		return nil
	}

	exponentialBackOff := backoff.NewExponentialBackOff()
	err = backoff.Retry(operation, exponentialBackOff)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate after retries: %v", err)
	}

	return cert, nil
}

// func (ac *ACMEClient) DownloadCertificate(order *acme.Order) (*x509.Certificate, error) {
// 	order, err := ac.client.GetOrder(context.Background(), ac.config.OrderURL)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get order: %v", err)
// 	}

// 	if order.Status != acme.StatusValid {
// 		return nil, fmt.Errorf("order status is not valid: %v", order.Status)
// 	}

// 	certChain, err := ac.client.FetchCert(context.Background(), order.CertificateURL, true)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to fetch certificate: %v", err)
// 	}

// 	cert, err := x509.ParseCertificate(certChain[0])
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse certificate: %v", err)
// 	}

// 	return cert, nil
// }
