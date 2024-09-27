package kvstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
)

func TestWebAuthn(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = webauthn_partition
		params.Serializer = serializer

		webAuthnDAO, err := NewWebAuthnDAO(params)
		assert.Nil(t, err)

		// Create new webauthn session data object
		userID := []byte("foo")
		sessionData := &webauthn.SessionData{
			UserID: userID,
		}
		sessionID := util.NewID(userID)

		// Marshall the session data to json
		sessionJSON, err := json.Marshal(sessionData)
		assert.Nil(t, err)

		// Create new session data blob entity
		sessionDataBlob := entities.CreateBlob(sessionID, sessionJSON, webauthn_partition)
		err = webAuthnDAO.Save(sessionDataBlob)
		assert.Nil(t, err)

		// Save the session data blob
		err = webAuthnDAO.Save(sessionDataBlob)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, webauthn_partition, sessionID)
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the session data blob
		persisted, err := webAuthnDAO.Get(sessionID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)

		var persistedSessionData webauthn.SessionData
		err = json.Unmarshal(persisted.Bytes, &persistedSessionData)
		assert.Nil(t, err)
		assert.True(t, bytes.Compare(persistedSessionData.UserID, sessionData.UserID) == 0)

		// Delete the webAuthn
		err = webAuthnDAO.Delete(sessionDataBlob)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = webAuthnDAO.Get(sessionID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}

func TestWebAuthnCount(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = webauthn_partition
		params.Serializer = serializer

		webAuthnDAO, err := NewWebAuthnDAO(params)
		assert.Nil(t, err)

		count := 1000
		for i := 0; i < count; i++ {

			// Create webauthn session data
			userID := []byte(fmt.Sprintf("user-%d", i))
			sessionData := &webauthn.SessionData{
				UserID: userID,
			}
			sessionID := util.NewID(userID)

			// Marshall the session data to json
			sessionJSON, err := json.Marshal(sessionData)
			assert.Nil(t, err)

			// Create new session data blob entity
			sessionDataBlob := entities.CreateBlob(sessionID, sessionJSON, webauthn_partition)
			err = webAuthnDAO.Save(sessionDataBlob)
			assert.Nil(t, err)
		}

		_count, err := webAuthnDAO.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestWebAuthnPage(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = webauthn_partition
		params.Serializer = serializer

		webAuthnDAO, err := NewWebAuthnDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, webAuthnDAO)

		count := 1000
		created := make([]*webauthn.SessionData, count)
		for i := 0; i < count; i++ {

			// Create webauthn session data
			userID := []byte(fmt.Sprintf("user-%d", i))
			sessionData := &webauthn.SessionData{
				UserID: userID,
			}
			sessionID := util.NewID(userID)

			// Marshall the session data to json
			sessionJSON, err := json.Marshal(sessionData)
			assert.Nil(t, err)

			// Create new session data blob entity
			sessionDataBlob := entities.CreateBlob(sessionID, sessionJSON, webauthn_partition)
			err = webAuthnDAO.Save(sessionDataBlob)
			assert.Nil(t, err)

			created[i] = sessionData

		}

		pageSize := 100

		page1, err := kvstore.Page(datastore.PageQuery{Page: 1, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page1.Entities))
		assert.True(t, page1.HasMore)
		// assert.Equal(t, created[0].ID, page1.Entities[0].ID)

		page2, err := kvstore.Page(datastore.PageQuery{Page: 2, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page2.Entities))
		assert.True(t, page2.HasMore)
		// assert.Equal(t, created[5].ID, page2.Entities[0].ID)

		page3, err := kvstore.Page(datastore.PageQuery{Page: 3, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page3.Entities))
		assert.True(t, page3.HasMore)
		// assert.Equal(t, created[10].ID, page3.Entities[0].ID)

		page4, err := kvstore.Page(datastore.PageQuery{Page: 10, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page4.Entities))
		assert.False(t, page4.HasMore)

		page5, err := kvstore.Page(datastore.PageQuery{Page: 11, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(page5.Entities))
		assert.False(t, page5.HasMore)
	}
}

func TestWebAuthnForEachPage(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = webauthn_partition
		params.Serializer = serializer

		webAuthnDAO, err := NewWebAuthnDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, webAuthnDAO)

		count := 1000
		created := make([]*webauthn.SessionData, count)
		for i := 0; i < count; i++ {

			// Create webauthn session data
			userID := []byte(fmt.Sprintf("user-%d", i))
			sessionData := &webauthn.SessionData{
				UserID: userID,
			}
			sessionID := util.NewID(userID)

			// Marshall the session data to json
			sessionJSON, err := json.Marshal(sessionData)
			assert.Nil(t, err)

			// Create new session data blob entity
			sessionDataBlob := entities.CreateBlob(sessionID, sessionJSON, webauthn_partition)
			err = webAuthnDAO.Save(sessionDataBlob)
			assert.Nil(t, err)

			created[i] = sessionData
		}

		pageSize := 100

		pages := 0
		pagerProcFunc := func(entities []*entities.Blob) error {
			pages++
			return nil
		}

		pageQuery := datastore.PageQuery{Page: 1, PageSize: pageSize}

		err = kvstore.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}