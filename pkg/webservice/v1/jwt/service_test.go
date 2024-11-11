package jwt

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {

	params := testServiceParams()
	params.KeyAttrs.KeyType = keystore.KEY_TYPE_TLS

	_, err := params.Keyring.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)
	assert.NotNil(t, service)

	user := entities.NewUser("root@localhost")
	token, err := service.GenerateToken(user)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	fmt.Println(token)
}
