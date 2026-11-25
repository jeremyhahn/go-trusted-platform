package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
)

// mustSecret wraps a literal test credential in a SecretValue.
func mustSecret(s string) *xkmstypes.SecretValue {
	sv, err := xkmstypes.NewLiteralSecretValue([]byte(s))
	if err != nil {
		panic(err)
	}
	return sv
}

// errMockProvision is returned by the tenant mocks, which do not model provisioning.
var errMockProvision = fmt.Errorf("tenant provisioning is not modelled by this mock")

func (m *mockIAMClientForTenant) Provision(context.Context, *sdkiam.ProvisionTenantRequest) (*sdkiam.ProvisionTenantResponse, error) {
	return nil, errMockProvision
}

func (m *mockIAMClientForServer) Provision(context.Context, *sdkiam.ProvisionTenantRequest) (*sdkiam.ProvisionTenantResponse, error) {
	return nil, errMockProvision
}

// lendSecretField lends one string field of sec (or the JSON of its Data when field is empty) to fn.
func lendSecretField(sec *secrets.Secret, err error, field string, fn func([]byte) error) error {
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("secret not found")
	}
	if field == "" {
		raw, err := json.Marshal(sec.Data)
		if err != nil {
			return err
		}
		return fn(raw)
	}
	value, ok := sec.Data[field].(string)
	if !ok {
		return fmt.Errorf("secret field %q is not a string", field)
	}
	return fn([]byte(value))
}

func (m *extSecretsClientMock) GetWithBytes(ctx context.Context, path, field string, fn func([]byte) error, opts ...secrets.GetOption) error {
	sec, err := m.Get(ctx, path, opts...)
	return lendSecretField(sec, err, field, fn)
}

func (c *paritySecretsClient) GetWithBytes(ctx context.Context, path, field string, fn func([]byte) error, opts ...secrets.GetOption) error {
	sec, err := c.Get(ctx, path, opts...)
	return lendSecretField(sec, err, field, fn)
}

func (c *jsonSecretsClient) GetWithBytes(ctx context.Context, path, field string, fn func([]byte) error, opts ...secrets.GetOption) error {
	sec, err := c.Get(ctx, path, opts...)
	return lendSecretField(sec, err, field, fn)
}
