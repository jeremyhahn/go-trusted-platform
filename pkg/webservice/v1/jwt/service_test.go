package jwt

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {

	keyring := createKeyring()
	config := testConfig()

	keyAttrs, err := keystore.KeyAttributesFromConfig(config.Key)
	assert.Nil(t, err)

	keyAttrs.KeyType = keystore.KEY_TYPE_TLS

	_, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)

	service, err := NewService(config, keyring, keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, service)

	user := entities.NewUser("root@localhost")
	token, err := service.GenerateToken(user)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	fmt.Println(token)
}
