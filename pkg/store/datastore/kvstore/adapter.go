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

package kvstore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// DefaultRequestTimeout is the default timeout for DAO operations.
const DefaultRequestTimeout = 30 * time.Second

// GenericDAO provides a key-value store backed implementation of datastore.GenericDAO.
// It stores entities as JSON documents keyed by their entity ID.
type GenericDAO[E entities.KeyValueEntity] struct {
	storage        Storage
	entityType     string
	logger         *logging.Logger
	newEntity      func() E
	requestTimeout time.Duration
	shardID        uint64
	partition      string

	// storageEntityType is the effective entity type used for storage operations.
	// When a partition is configured, this is "{partition}/{entityType}".
	// When no partition is set, this equals entityType.
	storageEntityType string
}

// DAOOption is a functional option for configuring a GenericDAO.
type DAOOption func(*daoConfig)

type daoConfig struct {
	requestTimeout time.Duration
	shardID        uint64
	partition      string
}

// WithRequestTimeout sets the request timeout for DAO operations.
func WithRequestTimeout(timeout time.Duration) DAOOption {
	return func(c *daoConfig) {
		c.requestTimeout = timeout
	}
}

// WithShard sets the shard ID for DAO operations.
// ShardID determines which Raft shard handles the entity's data.
// Default is 0, which uses the server's default shard.
func WithShard(shardID uint64) DAOOption {
	return func(c *daoConfig) {
		c.shardID = shardID
	}
}

// WithPartition sets the partition name for DAO operations.
// Partitions provide logical data isolation within a shard by prefixing
// the entity type with "{partition}/". This is complementary to
// TenantStorage, which provides tenant-level isolation at the storage layer.
// Default is empty string, which uses the entity type as-is.
func WithPartition(partition string) DAOOption {
	return func(c *daoConfig) {
		c.partition = partition
	}
}

// NewGenericDAO creates a new GenericDAO for the given entity type.
// The entityType is used as the partition/namespace for this DAO.
// When a partition is configured via WithPartition, the effective storage
// key becomes "{partition}/{entityType}" for logical data isolation.
func NewGenericDAO[E entities.KeyValueEntity](
	storage Storage,
	entityType string,
	newEntity func() E,
	logger *logging.Logger,
	opts ...DAOOption,
) *GenericDAO[E] {
	cfg := &daoConfig{
		requestTimeout: DefaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	storageEntityType := entityType
	if cfg.partition != "" {
		storageEntityType = cfg.partition + "/" + entityType
	}

	return &GenericDAO[E]{
		storage:           storage,
		entityType:        entityType,
		newEntity:         newEntity,
		logger:            logger,
		requestTimeout:    cfg.requestTimeout,
		shardID:           cfg.shardID,
		partition:         cfg.partition,
		storageEntityType: storageEntityType,
	}
}

// Save stores or updates an entity in the key-value store.
// If the entity's ID is 0, a new ID is generated based on the current timestamp.
func (d *GenericDAO[E]) Save(ctx context.Context, entity E) error {
	if entity.EntityID() == 0 {
		entity.SetEntityID(uint64(time.Now().UnixNano()))
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return ErrSerializationFailed{EntityType: d.entityType, Cause: err}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if err := d.storage.Put(ctx, d.storageEntityType, entity.EntityID(), data, d.shardID); err != nil {
		return err
	}

	d.logger.Debug("Entity saved", "type", d.storageEntityType, "id", entity.EntityID(), "shardID", d.shardID)
	return nil
}

// Get retrieves an entity by ID.
func (d *GenericDAO[E]) Get(ctx context.Context, id uint64) (E, error) {
	var zero E

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	data, found, err := d.storage.Get(ctx, d.storageEntityType, id, d.shardID)
	if err != nil {
		return zero, err
	}

	if !found {
		return zero, ErrNotFound{EntityType: d.entityType, ID: id}
	}

	entity := d.newEntity()
	if err := json.Unmarshal(data, entity); err != nil {
		return zero, ErrDeserializationFailed{EntityType: d.entityType, Cause: err}
	}

	return entity, nil
}

// Delete removes an entity from the key-value store.
func (d *GenericDAO[E]) Delete(ctx context.Context, entity E) error {
	id := entity.EntityID()
	if id == 0 {
		return ErrInvalidEntityID{EntityType: d.entityType, Reason: "cannot delete entity with ID 0"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if err := d.storage.Delete(ctx, d.storageEntityType, id, d.shardID); err != nil {
		return err
	}

	d.logger.Debug("Entity deleted", "type", d.storageEntityType, "id", id, "shardID", d.shardID)
	return nil
}

// Count returns the total number of entities of this type.
func (d *GenericDAO[E]) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, d.storageEntityType, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, err
		}

		count += len(svcEntities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Page retrieves a page of entities.
func (d *GenericDAO[E]) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[E], error) {
	result := datastore.PageResult[E]{
		Entities: make([]E, 0, pageQuery.PageSize),
		Page:     pageQuery.Page,
		PageSize: pageQuery.PageSize,
		HasMore:  false,
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	toSkip := (pageQuery.Page - 1) * pageQuery.PageSize
	fetchSize := uint64(1000)

	var allEntities []E
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, d.storageEntityType, fetchSize, pageToken, d.shardID)
		if err != nil {
			return result, err
		}

		for _, svcEntity := range svcEntities {
			entity := d.newEntity()
			if err := json.Unmarshal(svcEntity.Data, entity); err != nil {
				d.logger.Warn("Failed to deserialize entity", "type", d.storageEntityType, "id", svcEntity.ID, "error", err)
				continue
			}
			allEntities = append(allEntities, entity)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	totalItems := len(allEntities)
	result.Total = totalItems

	if toSkip >= totalItems {
		return result, nil
	}

	endIdx := toSkip + pageQuery.PageSize
	if endIdx > totalItems {
		endIdx = totalItems
	}

	result.Entities = allEntities[toSkip:endIdx]
	result.HasMore = endIdx < totalItems

	return result, nil
}

// ForEachPage iterates over all entities page by page, calling the processor function for each page.
// The callback receives the full PageResult including pagination metadata.
// Return nil to continue to the next page, or an error to stop iteration.
func (d *GenericDAO[E]) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, fn datastore.PagerFunc[E]) error {
	currentPage := pageQuery.Page
	if currentPage < 1 {
		currentPage = 1
	}

	for {
		query := datastore.PageQuery{
			Page:      currentPage,
			PageSize:  pageQuery.PageSize,
			SortOrder: pageQuery.SortOrder,
		}

		result, err := d.Page(ctx, query)
		if err != nil {
			return err
		}

		if len(result.Entities) > 0 {
			if err := fn(result); err != nil {
				if err == datastore.ErrStopIteration {
					return nil
				}
				return err
			}
		}

		if !result.HasMore || len(result.Entities) == 0 {
			break
		}

		currentPage++
	}

	return nil
}

// EntityType returns the entity type name used for this DAO.
func (d *GenericDAO[E]) EntityType() string {
	return d.entityType
}

// StorageEntityType returns the effective entity type used for storage operations.
// When a partition is configured, this includes the partition prefix.
func (d *GenericDAO[E]) StorageEntityType() string {
	return d.storageEntityType
}

// ShardID returns the shard ID configured for this DAO.
func (d *GenericDAO[E]) ShardID() uint64 {
	return d.shardID
}

// Partition returns the partition name configured for this DAO.
func (d *GenericDAO[E]) Partition() string {
	return d.partition
}
