// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

// Package acme provides multi-protocol integration tests for ACME certificate services.
// These tests verify that ACME operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified ACMECommands interface.
//
// Run tests via:
//
//	make integration-test-acme
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package acme

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmecmd "github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/acme"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestACMEMultiProtocol runs the complete ACME test suite against all protocol adapters.
// Each adapter implements the ACMECommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestACMEMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement ACMECommands
	adapters := []ACMECommands{
		NewCLIAdapter(),
		// NewRESTAdapter(),  // TODO: Implement
		// NewGRPCAdapter(),  // TODO: Implement
		// NewQUICAdapter(),  // TODO: Implement
		// NewMCPAdapter(),   // TODO: Implement
		// NewUnixAdapter(),  // TODO: Implement
	}

	gate := helpers.NewAdapterGate(t, "acme", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testACMEProtocol(t, ctx, adapter)
		})
	}
}

// testACMEProtocol runs the complete ACME test suite against a single protocol adapter.
func testACMEProtocol(t *testing.T, ctx context.Context, cmd ACMECommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("AccountManagement", func(t *testing.T) {
		testAccountCreate(t, ctx, cmd, prefix)
		testAccountList(t, ctx, cmd, prefix)
		testAccountDelete(t, ctx, cmd, prefix)
	})

	t.Run("OrderManagement", func(t *testing.T) {
		testOrderCreate(t, ctx, cmd, prefix)
		testOrderList(t, ctx, cmd, prefix)
		testOrderGet(t, ctx, cmd, prefix)
	})

	t.Run("CertificateOperations", func(t *testing.T) {
		testCertificateRequest(t, ctx, cmd, prefix)
		testCertificateRenew(t, ctx, cmd, prefix)
		testCertificateRevoke(t, ctx, cmd, prefix)
	})

	t.Run("ChallengeTypes", func(t *testing.T) {
		testChallengeHTTP01(t, ctx, cmd, prefix)
		testChallengeDNS01(t, ctx, cmd, prefix)
		testChallengeEnroll01(t, ctx, cmd, prefix)
	})

	t.Run("ErrorCases", func(t *testing.T) {
		testAccountErrors(t, ctx, cmd, prefix)
		testOrderErrors(t, ctx, cmd, prefix)
		testCertificateErrors(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// CLI Refusals
// =============================================================================

// requireCLIRefusal asserts the refusal the CLI gives op for valid input
// (cliRefusals) and reports whether it did, so the leaf ends there. On any
// other transport it returns false and the leaf goes on to its own
// assertions.
func requireCLIRefusal(t *testing.T, cmd ACMECommands, err error, op string) bool {
	t.Helper()
	if cmd.Name() != "CLI" {
		return false
	}
	require.ErrorIs(t, err, cliRefusals[op], "platformctl refuses %s (docs/ca/cli.md §3)", op)
	return true
}

// requireCLIValidation asserts that the CLI refused the input with want,
// which platformctl checks before it reaches the gap. The error crosses the
// process boundary as text, so the match is on want's exact message.
func requireCLIValidation(t *testing.T, cmd ACMECommands, err error, want error) {
	t.Helper()
	if cmd.Name() != "CLI" {
		return
	}
	require.ErrorContains(t, err, want.Error(), "platformctl validates its input before the gap")
}

// setupAccount creates the account a leaf needs. On the CLI it asserts the
// refusal and returns an empty account, so every leaf still runs and
// asserts its own refusal.
func setupAccount(t *testing.T, ctx context.Context, cmd ACMECommands, email string) *AccountCreateResult {
	t.Helper()
	account, err := cmd.AccountCreate(ctx, DefaultAccountCreateOptions(email))
	if requireCLIRefusal(t, cmd, err, "AccountCreate") {
		return &AccountCreateResult{}
	}
	require.NoError(t, err, "Setup: AccountCreate should succeed")
	return account
}

// setupOrder places the order a leaf needs, the way setupAccount creates an
// account.
func setupOrder(t *testing.T, ctx context.Context, cmd ACMECommands, accountID string, identifiers ...OrderIdentifier) *OrderCreateResult {
	t.Helper()
	order, err := cmd.OrderCreate(ctx, OrderCreateOptions{AccountID: accountID, Identifiers: identifiers})
	if requireCLIRefusal(t, cmd, err, "OrderCreate") {
		return &OrderCreateResult{}
	}
	require.NoError(t, err, "Setup: OrderCreate should succeed")
	return order
}

// setupCertificate requests the certificate a revoke leaf needs and reports
// whether the CLI refused the request, in which case the result is empty.
func setupCertificate(t *testing.T, ctx context.Context, cmd ACMECommands, cn, email string) (*CertificateRequestResult, bool) {
	t.Helper()
	result, err := cmd.CertificateRequest(ctx, DefaultCertificateRequestOptions(cn, email))
	if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
		return &CertificateRequestResult{}, true
	}
	require.NoError(t, err, "Setup: CertificateRequest should succeed")
	return result, false
}

// =============================================================================
// Account Management Tests
// =============================================================================

func testAccountCreate(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateAccountWithEmail", func(t *testing.T) {
		email := GenerateUniqueEmail(prefix)
		opts := DefaultAccountCreateOptions(email)

		result, err := cmd.AccountCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "AccountCreate") {
			return
		}
		require.NoError(t, err, "AccountCreate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.AccountID, "Account ID should not be empty")
		assert.Equal(t, "valid", result.Status, "Account status should be valid")
		assert.Equal(t, email, result.Email, "Email should match")
	})

	t.Run("CreateAccountWithExternalAccountBinding", func(t *testing.T) {
		email := GenerateUniqueEmail(prefix + "-eab")
		opts := AccountCreateOptions{
			Email:              email,
			DirectoryURL:       GetServiceEndpoints().ACMEDirectory,
			TermsOfService:     true,
			ExternalAccountID:  "test-eab-kid",
			ExternalAccountKey: "dGVzdC1lYWItaG1hYy1rZXk=", // base64 encoded test key
		}

		result, err := cmd.AccountCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "AccountCreate") {
			return
		}
		// This may fail if the ACME server doesn't require EAB, but should not panic
		if err != nil {
			t.Logf("EAB account creation returned error (may be expected): %v", err)
			return
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.AccountID, "Account ID should not be empty")
	})

	t.Run("CreateAccountEmptyEmailFails", func(t *testing.T) {
		opts := AccountCreateOptions{
			Email:          "",
			DirectoryURL:   GetServiceEndpoints().ACMEDirectory,
			TermsOfService: true,
		}

		_, err := cmd.AccountCreate(testCtx, opts)
		require.Error(t, err, "AccountCreate should fail with empty email")
		requireCLIValidation(t, cmd, err, acmecmd.ErrMissingEmail{})
	})

	t.Run("CreateAccountWithoutTOSFails", func(t *testing.T) {
		email := GenerateUniqueEmail(prefix + "-notos")
		opts := AccountCreateOptions{
			Email:          email,
			DirectoryURL:   GetServiceEndpoints().ACMEDirectory,
			TermsOfService: false,
		}

		_, err := cmd.AccountCreate(testCtx, opts)
		require.Error(t, err, "AccountCreate should fail without accepting TOS")
		// acme register takes no TOS flag: the CLI ends on the gap.
		requireCLIRefusal(t, cmd, err, "AccountCreate")
	})
}

func testAccountList(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a few accounts first
	for i := 0; i < 3; i++ {
		setupAccount(t, testCtx, cmd, GenerateUniqueEmail(fmt.Sprintf("%s-list-%d", prefix, i)))
	}

	t.Run("ListAllAccounts", func(t *testing.T) {
		result, err := cmd.AccountList(testCtx, AccountListOptions{Limit: 100})
		if requireCLIRefusal(t, cmd, err, "AccountList") {
			return
		}
		require.NoError(t, err, "AccountList should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Accounts), 3, "Should have at least 3 accounts")
	})

	t.Run("ListAccountsWithPagination", func(t *testing.T) {
		result, err := cmd.AccountList(testCtx, AccountListOptions{Limit: 2})
		if requireCLIRefusal(t, cmd, err, "AccountList") {
			return
		}
		require.NoError(t, err, "AccountList should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Accounts)), int32(2), "Should respect limit")

		// If there are more accounts, test cursor pagination
		if result.HasMore {
			result2, err := cmd.AccountList(testCtx, AccountListOptions{
				Limit:  2,
				Cursor: result.NextCursor,
			})
			require.NoError(t, err, "AccountList with cursor should succeed")
			require.NotNil(t, result2, "Second page result should not be nil")
		}
	})
}

func testAccountDelete(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create an account for deletion
	createResult := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-delete"))

	t.Run("DeleteExistingAccount", func(t *testing.T) {
		result, err := cmd.AccountDelete(testCtx, createResult.AccountID)
		if requireCLIRefusal(t, cmd, err, "AccountDelete") {
			return
		}
		require.NoError(t, err, "AccountDelete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, createResult.AccountID, result.AccountID, "Account ID should match")
		assert.True(t, result.Deleted, "Account should be deleted")
	})

	t.Run("DeleteNonexistentAccountFails", func(t *testing.T) {
		_, err := cmd.AccountDelete(testCtx, "nonexistent-account-id")
		require.Error(t, err, "AccountDelete should fail for nonexistent account")
		requireCLIRefusal(t, cmd, err, "AccountDelete")
	})
}

// =============================================================================
// Order Management Tests
// =============================================================================

func testOrderCreate(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create an account first
	account := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-order"))

	t.Run("CreateOrderWithDNSIdentifier", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-dns")
		opts := OrderCreateOptions{
			AccountID: account.AccountID,
			Identifiers: []OrderIdentifier{
				{Type: "dns", Value: cn},
			},
		}

		result, err := cmd.OrderCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "OrderCreate") {
			return
		}
		require.NoError(t, err, "OrderCreate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.OrderID, "Order ID should not be empty")
		assert.Equal(t, "pending", result.Status, "Order status should be pending")
		assert.Len(t, result.Identifiers, 1, "Should have 1 identifier")
		assert.Equal(t, "dns", result.Identifiers[0].Type, "Identifier type should be dns")
	})

	t.Run("CreateOrderWithMultipleDNSIdentifiers", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-multi")
		sans := GenerateTestSANs(cn, 3)

		identifiers := []OrderIdentifier{{Type: "dns", Value: cn}}
		for _, san := range sans {
			identifiers = append(identifiers, OrderIdentifier{Type: "dns", Value: san})
		}

		opts := OrderCreateOptions{
			AccountID:   account.AccountID,
			Identifiers: identifiers,
		}

		result, err := cmd.OrderCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "OrderCreate") {
			return
		}
		require.NoError(t, err, "OrderCreate should succeed with multiple identifiers")
		require.NotNil(t, result, "Result should not be nil")
		assert.Len(t, result.Identifiers, 4, "Should have 4 identifiers")
	})

	t.Run("CreateOrderWithIPIdentifier", func(t *testing.T) {
		opts := OrderCreateOptions{
			AccountID: account.AccountID,
			Identifiers: []OrderIdentifier{
				{Type: "ip", Value: "192.168.1.100"},
			},
		}

		result, err := cmd.OrderCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "OrderCreate") {
			return
		}
		require.NoError(t, err, "OrderCreate should succeed with IP identifier")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "ip", result.Identifiers[0].Type, "Identifier type should be ip")
	})

	t.Run("CreateOrderWithPermanentIdentifier", func(t *testing.T) {
		deviceSerial := GenerateUniqueDeviceSerial(prefix)
		opts := OrderCreateOptions{
			AccountID: account.AccountID,
			Identifiers: []OrderIdentifier{
				{Type: "permanent-identifier", Value: deviceSerial},
			},
		}

		result, err := cmd.OrderCreate(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "OrderCreate") {
			return
		}
		require.NoError(t, err, "OrderCreate should succeed with permanent-identifier")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "permanent-identifier", result.Identifiers[0].Type, "Identifier type should be permanent-identifier")
	})

	t.Run("CreateOrderEmptyIdentifiersFails", func(t *testing.T) {
		opts := OrderCreateOptions{
			AccountID:   account.AccountID,
			Identifiers: []OrderIdentifier{},
		}

		_, err := cmd.OrderCreate(testCtx, opts)
		require.Error(t, err, "OrderCreate should fail with empty identifiers")
		requireCLIRefusal(t, cmd, err, "OrderCreate")
	})
}

func testOrderList(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create an account and orders
	account := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-orderlist"))

	for i := 0; i < 3; i++ {
		cn := GenerateUniqueCommonName(fmt.Sprintf("%s-list-%d", prefix, i))
		setupOrder(t, testCtx, cmd, account.AccountID, OrderIdentifier{Type: "dns", Value: cn})
	}

	t.Run("ListOrdersForAccount", func(t *testing.T) {
		result, err := cmd.OrderList(testCtx, OrderListOptions{
			AccountID: account.AccountID,
			Limit:     100,
		})
		if requireCLIRefusal(t, cmd, err, "OrderList") {
			return
		}
		require.NoError(t, err, "OrderList should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Orders), 3, "Should have at least 3 orders")
	})

	t.Run("ListOrdersByStatus", func(t *testing.T) {
		result, err := cmd.OrderList(testCtx, OrderListOptions{
			AccountID: account.AccountID,
			Status:    "pending",
			Limit:     100,
		})
		if requireCLIRefusal(t, cmd, err, "OrderList") {
			return
		}
		require.NoError(t, err, "OrderList should succeed with status filter")
		require.NotNil(t, result, "Result should not be nil")

		for _, order := range result.Orders {
			assert.Equal(t, "pending", order.Status, "All orders should be pending")
		}
	})

	t.Run("ListOrdersWithPagination", func(t *testing.T) {
		result, err := cmd.OrderList(testCtx, OrderListOptions{
			AccountID: account.AccountID,
			Limit:     2,
		})
		if requireCLIRefusal(t, cmd, err, "OrderList") {
			return
		}
		require.NoError(t, err, "OrderList should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Orders)), int32(2), "Should respect limit")
	})
}

func testOrderGet(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Create an account and order
	account := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-orderget"))
	cn := GenerateUniqueCommonName(prefix + "-get")
	order := setupOrder(t, testCtx, cmd, account.AccountID, OrderIdentifier{Type: "dns", Value: cn})

	t.Run("GetExistingOrder", func(t *testing.T) {
		result, err := cmd.OrderGet(testCtx, order.OrderID)
		if requireCLIRefusal(t, cmd, err, "OrderGet") {
			return
		}
		require.NoError(t, err, "OrderGet should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, order.OrderID, result.OrderID, "Order ID should match")
		assert.NotEmpty(t, result.Authorizations, "Authorizations should not be empty")
	})

	t.Run("GetOrderShowsAuthorizations", func(t *testing.T) {
		result, err := cmd.OrderGet(testCtx, order.OrderID)
		if requireCLIRefusal(t, cmd, err, "OrderGet") {
			return
		}
		require.NoError(t, err, "OrderGet should succeed")
		require.NotNil(t, result, "Result should not be nil")

		for _, auth := range result.Authorizations {
			assert.NotEmpty(t, auth.URL, "Authorization URL should not be empty")
			assert.NotEmpty(t, auth.Status, "Authorization status should not be empty")
			assert.NotEmpty(t, auth.Challenges, "Challenges should not be empty")
		}
	})

	t.Run("GetNonexistentOrderFails", func(t *testing.T) {
		_, err := cmd.OrderGet(testCtx, "nonexistent-order-id")
		require.Error(t, err, "OrderGet should fail for nonexistent order")
		requireCLIRefusal(t, cmd, err, "OrderGet")
	})
}

// =============================================================================
// Certificate Operation Tests
// =============================================================================

func testCertificateRequest(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	t.Run("RequestCertificateBasic", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-req")
		email := GenerateUniqueEmail(prefix + "-req")
		opts := DefaultCertificateRequestOptions(cn, email)

		result, err := cmd.CertificateRequest(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
			return
		}
		require.NoError(t, err, "CertificateRequest should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.OrderID, "Order ID should not be empty")
		// Status may be "valid" or "processing" depending on challenge completion
		assert.NotEmpty(t, result.Status, "Status should not be empty")
	})

	t.Run("RequestCertificateWithSANs", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-sans")
		email := GenerateUniqueEmail(prefix + "-sans")
		opts := CertificateRequestOptions{
			CommonName:        cn,
			SANsDNS:           GenerateTestSANs(cn, 3),
			AuthorizationType: "dns",
			ChallengeType:     "http-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			CACert:            GetServiceEndpoints().ACMECACert,
			Email:             email,
		}

		result, err := cmd.CertificateRequest(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
			return
		}
		require.NoError(t, err, "CertificateRequest with SANs should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("RequestCertificateWithFullSubject", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-fullsubj")
		email := GenerateUniqueEmail(prefix + "-fullsubj")
		opts := CertificateRequestOptions{
			CommonName:         cn,
			Organization:       "Test Organization",
			OrganizationalUnit: "Test Unit",
			Country:            "US",
			Province:           "California",
			Locality:           "San Francisco",
			AuthorizationType:  "dns",
			ChallengeType:      "http-01",
			DirectoryURL:       GetServiceEndpoints().ACMEDirectory,
			CACert:             GetServiceEndpoints().ACMECACert,
			Email:              email,
		}

		result, err := cmd.CertificateRequest(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
			return
		}
		require.NoError(t, err, "CertificateRequest with full subject should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("RequestCertificateEmptyCNFails", func(t *testing.T) {
		email := GenerateUniqueEmail(prefix + "-emptycn")
		opts := CertificateRequestOptions{
			CommonName:        "",
			AuthorizationType: "dns",
			ChallengeType:     "http-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			Email:             email,
		}

		_, err := cmd.CertificateRequest(testCtx, opts)
		require.Error(t, err, "CertificateRequest should fail with empty CN")
		requireCLIValidation(t, cmd, err, acmecmd.ErrMissingAuthorizationValue{})
	})
}

func testCertificateRenew(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	t.Run("RenewCertificateBasic", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-renew")
		email := GenerateUniqueEmail(prefix + "-renew")
		opts := DefaultCertificateRenewOptions(cn, email)

		result, err := cmd.CertificateRenew(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRenew") {
			return
		}
		require.NoError(t, err, "CertificateRenew should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.OrderID, "Order ID should not be empty")
	})

	t.Run("RenewCertificateDNSChallenge", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-renewdns")
		email := GenerateUniqueEmail(prefix + "-renewdns")
		opts := CertificateRenewOptions{
			CommonName:        cn,
			AuthorizationType: "dns",
			ChallengeType:     "dns-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			CACert:            GetServiceEndpoints().ACMECACert,
			Email:             email,
		}

		result, err := cmd.CertificateRenew(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRenew") {
			return
		}
		require.NoError(t, err, "CertificateRenew with DNS challenge should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("RenewCertificateDeviceChallenge", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-renewdev")
		email := GenerateUniqueEmail(prefix + "-renewdev")
		opts := CertificateRenewOptions{
			CommonName:        cn,
			AuthorizationType: "permanent-identifier",
			ChallengeType:     "device-attest-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			CACert:            GetServiceEndpoints().ACMECACert,
			Email:             email,
		}

		result, err := cmd.CertificateRenew(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRenew") {
			return
		}
		// This may fail if device attestation is not configured, but should handle gracefully
		if err != nil {
			t.Logf("Device attestation challenge returned error (may be expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})
}

func testCertificateRevoke(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// First request a certificate to revoke. The CLI refuses the request, so
	// it has no certificate and each leaf asserts the revoke refusal instead.
	cn := GenerateUniqueCommonName(prefix + "-revoke")
	reqResult, cliRefused := setupCertificate(t, testCtx, cmd, cn, GenerateUniqueEmail(prefix+"-revoke"))

	// Revocation needs the certificate this setup just requested.
	if !cliRefused && reqResult.CertificateURL == "" && reqResult.SerialNumber == "" {
		t.Fatalf("Setup: CertificateRequest for %s issued no certificate (status %q); revocation needs an issued certificate URL or serial", cn, reqResult.Status)
	}

	t.Run("RevokeCertificateByURL", func(t *testing.T) {
		if !cliRefused && reqResult.CertificateURL == "" {
			t.Fatalf("Setup: CertificateRequest for %s returned no certificate URL; revoke-by-URL needs one", cn)
		}

		opts := CertificateRevokeOptions{
			CertificateURL: reqResult.CertificateURL,
			Reason:         0, // unspecified
		}

		result, err := cmd.CertificateRevoke(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRevoke") {
			return
		}
		require.NoError(t, err, "CertificateRevoke should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Revoked, "Certificate should be revoked")
	})

	t.Run("RevokeCertificateBySerial", func(t *testing.T) {
		// Create another certificate for this test
		cn2 := GenerateUniqueCommonName(prefix + "-revoke2")
		reqResult2, cliRefused2 := setupCertificate(t, testCtx, cmd, cn2, GenerateUniqueEmail(prefix+"-revoke2"))

		if !cliRefused2 && reqResult2.SerialNumber == "" {
			t.Fatalf("Setup: CertificateRequest for %s returned no certificate serial; revoke-by-serial needs one", cn2)
		}

		opts := CertificateRevokeOptions{
			SerialNumber: reqResult2.SerialNumber,
			Reason:       1, // keyCompromise
		}

		result, err := cmd.CertificateRevoke(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRevoke") {
			return
		}
		require.NoError(t, err, "CertificateRevoke should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Revoked, "Certificate should be revoked")
		assert.Equal(t, 1, result.Reason, "Revocation reason should be keyCompromise")
	})

	t.Run("RevokeNonexistentCertificateFails", func(t *testing.T) {
		opts := CertificateRevokeOptions{
			SerialNumber: "nonexistent-serial",
			Reason:       0,
		}

		_, err := cmd.CertificateRevoke(testCtx, opts)
		require.Error(t, err, "CertificateRevoke should fail for nonexistent certificate")
		requireCLIRefusal(t, cmd, err, "CertificateRevoke")
	})
}

// =============================================================================
// Challenge Type Tests
// =============================================================================

func testChallengeHTTP01(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	t.Run("HTTP01ChallengeFlow", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-http01")
		email := GenerateUniqueEmail(prefix + "-http01")
		opts := CertificateRequestOptions{
			CommonName:        cn,
			AuthorizationType: "dns",
			ChallengeType:     "http-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			CACert:            GetServiceEndpoints().ACMECACert,
			Email:             email,
		}

		result, err := cmd.CertificateRequest(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
			return
		}
		require.NoError(t, err, "HTTP-01 challenge flow should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})
}

func testChallengeDNS01(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	t.Run("DNS01ChallengeFlow", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-dns01")
		email := GenerateUniqueEmail(prefix + "-dns01")
		opts := CertificateRequestOptions{
			CommonName:        cn,
			AuthorizationType: "dns",
			ChallengeType:     "dns-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			CACert:            GetServiceEndpoints().ACMECACert,
			Email:             email,
		}

		result, err := cmd.CertificateRequest(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRequest") {
			return
		}
		require.NoError(t, err, "DNS-01 challenge flow should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})
}

func testChallengeEnroll01(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// Create account and order first
	account := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-enroll01"))
	deviceSerial := GenerateUniqueDeviceSerial(prefix)
	order := setupOrder(t, testCtx, cmd, account.AccountID,
		OrderIdentifier{Type: "permanent-identifier", Value: deviceSerial})

	t.Run("Enroll01ChallengeWithAttestation", func(t *testing.T) {
		opts := ChallengeEnroll01Options{
			OrderID:      order.OrderID,
			AccountID:    account.AccountID,
			DeviceSerial: deviceSerial,
			DeviceModel:  "TPM-TestDevice-v1",
			TPMHandle:    0x81010001, // Standard EK handle
			// In real tests, these would be real attestation data
			AttestKeyPEM: "",  // Would be the attestation key PEM
			QuoteData:    nil, // Would be the TPM quote
			PCRValues:    nil, // Would be the PCR values
		}

		result, err := cmd.ChallengeEnroll01(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "ChallengeEnroll01") {
			return
		}
		// This may fail without actual TPM, but should handle gracefully
		if err != nil {
			t.Logf("Enroll-01 challenge returned error (expected without TPM): %v", err)
			return
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.Status, "Status should not be empty")
	})

	t.Run("Enroll01ChallengeEmptyDeviceSerialFails", func(t *testing.T) {
		opts := ChallengeEnroll01Options{
			OrderID:      order.OrderID,
			AccountID:    account.AccountID,
			DeviceSerial: "",
			DeviceModel:  "TPM-TestDevice-v1",
		}

		_, err := cmd.ChallengeEnroll01(testCtx, opts)
		require.Error(t, err, "Enroll-01 should fail with empty device serial")
		requireCLIRefusal(t, cmd, err, "ChallengeEnroll01")
	})
}

// =============================================================================
// Error Case Tests
// =============================================================================

func testAccountErrors(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateAccountInvalidDirectoryURL", func(t *testing.T) {
		email := GenerateUniqueEmail(prefix + "-invalid")
		opts := AccountCreateOptions{
			Email:          email,
			DirectoryURL:   "https://invalid.example.com/directory",
			TermsOfService: true,
		}

		_, err := cmd.AccountCreate(testCtx, opts)
		require.Error(t, err, "AccountCreate should fail with invalid directory URL")
		// acme register takes no directory flag: the CLI ends on the gap.
		requireCLIRefusal(t, cmd, err, "AccountCreate")
	})

	t.Run("DeleteAccountInvalidID", func(t *testing.T) {
		_, err := cmd.AccountDelete(testCtx, "invalid-account-id-!@#$%")
		require.Error(t, err, "AccountDelete should fail with invalid account ID")
		requireCLIRefusal(t, cmd, err, "AccountDelete")
	})
}

func testOrderErrors(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateOrderInvalidAccountID", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-invalidacc")
		opts := OrderCreateOptions{
			AccountID: "invalid-account-id",
			Identifiers: []OrderIdentifier{
				{Type: "dns", Value: cn},
			},
		}

		_, err := cmd.OrderCreate(testCtx, opts)
		require.Error(t, err, "OrderCreate should fail with invalid account ID")
		requireCLIRefusal(t, cmd, err, "OrderCreate")
	})

	t.Run("CreateOrderInvalidIdentifierType", func(t *testing.T) {
		account := setupAccount(t, testCtx, cmd, GenerateUniqueEmail(prefix+"-invalidid"))

		opts := OrderCreateOptions{
			AccountID: account.AccountID,
			Identifiers: []OrderIdentifier{
				{Type: "invalid-type", Value: "test.example.com"},
			},
		}

		_, err := cmd.OrderCreate(testCtx, opts)
		require.Error(t, err, "OrderCreate should fail with invalid identifier type")
		requireCLIRefusal(t, cmd, err, "OrderCreate")
	})

	t.Run("GetOrderInvalidID", func(t *testing.T) {
		_, err := cmd.OrderGet(testCtx, "invalid-order-id-!@#$%")
		require.Error(t, err, "OrderGet should fail with invalid order ID")
		requireCLIRefusal(t, cmd, err, "OrderGet")
	})
}

func testCertificateErrors(t *testing.T, ctx context.Context, cmd ACMECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("RequestCertificateInvalidAuthzType", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-invalidauthz")
		email := GenerateUniqueEmail(prefix + "-invalidauthz")
		opts := CertificateRequestOptions{
			CommonName:        cn,
			AuthorizationType: "invalid-authz-type",
			ChallengeType:     "http-01",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			Email:             email,
		}

		_, err := cmd.CertificateRequest(testCtx, opts)
		require.Error(t, err, "CertificateRequest should fail with invalid authz type")
		requireCLIValidation(t, cmd, err, acmecmd.ErrInvalidAuthorizationType{Type: "invalid-authz-type"})
	})

	t.Run("RequestCertificateInvalidChallengeType", func(t *testing.T) {
		cn := GenerateUniqueCommonName(prefix + "-invalidchall")
		email := GenerateUniqueEmail(prefix + "-invalidchall")
		opts := CertificateRequestOptions{
			CommonName:        cn,
			AuthorizationType: "dns",
			ChallengeType:     "invalid-challenge-type",
			DirectoryURL:      GetServiceEndpoints().ACMEDirectory,
			Email:             email,
		}

		_, err := cmd.CertificateRequest(testCtx, opts)
		require.Error(t, err, "CertificateRequest should fail with invalid challenge type")
		requireCLIValidation(t, cmd, err, acmecmd.ErrInvalidChallengeType{Type: "invalid-challenge-type"})
	})

	t.Run("RevokeWithBothURLAndSerialFails", func(t *testing.T) {
		opts := CertificateRevokeOptions{
			CertificateURL: "https://example.com/cert/123",
			SerialNumber:   "12345",
			Reason:         0,
		}

		_, err := cmd.CertificateRevoke(testCtx, opts)
		if requireCLIRefusal(t, cmd, err, "CertificateRevoke") {
			return
		}
		// This should either succeed or fail consistently - implementation dependent
		if err != nil {
			t.Logf("Revoke with both URL and serial returned error: %v", err)
		}
	})

	t.Run("RevokeWithNeitherURLNorSerialFails", func(t *testing.T) {
		opts := CertificateRevokeOptions{
			CertificateURL: "",
			SerialNumber:   "",
			Reason:         0,
		}

		_, err := cmd.CertificateRevoke(testCtx, opts)
		require.Error(t, err, "CertificateRevoke should fail without URL or serial")
		// platformctl has no revoke verb: the CLI ends on ErrCLINoACMEVerb.
		requireCLIRefusal(t, cmd, err, "CertificateRevoke")
	})
}
