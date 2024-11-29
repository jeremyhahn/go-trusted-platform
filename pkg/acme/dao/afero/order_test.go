package afero

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func aferoTestParams[E any]() *datastore.Params[E] {
	return &datastore.Params[E]{
		Fs:             afero.NewMemMapFs(),
		Logger:         logging.NewLogger(slog.LevelDebug, nil),
		Partition:      "orders",
		RootDir:        "./test",
		ReadBufferSize: 50,
	}
}

func TestGetByOrderID(t *testing.T) {

	serializers := []serializer.Serializer[*entities.ACMEOrder]{
		serializer.NewJSONSerializer[*entities.ACMEOrder](),
		serializer.NewYAMLSerializer[*entities.ACMEOrder](),
	}

	for _, serializer := range serializers {

		params := aferoTestParams[*entities.ACMEOrder]()
		// params.Partition = acme_order_partition
		params.Serializer = serializer
		params.Fs = afero.NewOsFs()

		orderDAO, err := NewACMEOrderDAO(params, 1)
		assert.Nil(t, err)

		// Create new order
		order := &entities.ACMEOrder{
			ID:        1,
			AccountID: 1,
			Status:    "pending",
			Identifiers: []entities.ACMEIdentifier{
				{
					Type:  "test-type",
					Value: "test-value",
				},
			},
			Expires:   time.Now().String(),
			NotBefore: string("not-before-test"),
			NotAfter:  string("not-after-test"),
			Error:     nil,
			URL:       "http://test.com",
		}
		err = orderDAO.Save(order)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d%s",
			params.RootDir, params.Partition, order.ID, serializer.Extension())
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Create a 2nd order
		order2 := &entities.ACMEOrder{
			ID:        2,
			AccountID: 1,
			Status:    "pending",
			Identifiers: []entities.ACMEIdentifier{
				{
					Type:  "test-type",
					Value: "test-value",
				},
			},
			Expires:   time.Now().String(),
			NotBefore: string("not-before-test"),
			NotAfter:  string("not-after-test"),
			Error:     nil,
			URL:       "http://test.com",
		}
		err = orderDAO.Save(order2)
		assert.Nil(t, err)

		// Ensure GetByAccountID works
		pageResult, err := orderDAO.GetByAccountID(datastore.ConsistencyLevelLocal)
		assert.Nil(t, err)
		assert.Equal(t, 2, len(pageResult.Entities))

		// Retrieve the order
		persisted, err := orderDAO.Get(order.ID, datastore.ConsistencyLevelLocal)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == order.ID)

		// Delete the orders
		err = orderDAO.Delete(order)
		assert.Nil(t, err)
		err = orderDAO.Delete(order2)
		assert.Nil(t, err)

		// Ensure they're deleted
		_, err = orderDAO.Get(order.ID, datastore.ConsistencyLevelLocal)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))

		_, err = orderDAO.Get(order2.ID, datastore.ConsistencyLevelLocal)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}
