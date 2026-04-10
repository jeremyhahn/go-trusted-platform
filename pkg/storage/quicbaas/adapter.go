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

package quicbaas

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// Default request timeout for DAO operations
const DefaultRequestTimeout = 30 * time.Second

// GenericDAO provides a QuicBaaS-backed implementation of datastore.GenericDAO.
// It stores entities as JSON documents keyed by their entity ID.
type GenericDAO[E entities.KeyValueEntity] struct {
	storage        Storage
	entityType     string
	logger         *logging.Logger
	newEntity      func() E // Factory function to create new entity instances
	requestTimeout time.Duration
	shardID        uint64
	partition      string
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
// Partitions provide logical data isolation within a shard.
// Default is empty string, which uses the default partition.
func WithPartition(partition string) DAOOption {
	return func(c *daoConfig) {
		c.partition = partition
	}
}

// NewGenericDAO creates a new GenericDAO for the given entity type.
// The entityType is used as the QuicBaaS partition/namespace for this DAO.
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

	return &GenericDAO[E]{
		storage:        storage,
		entityType:     entityType,
		newEntity:      newEntity,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
		partition:      cfg.partition,
	}
}

// checkContext returns an ErrContextCancelled if the context is already done.
func (d *GenericDAO[E]) checkContext(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return ErrContextCancelled{Operation: operation, Cause: err}
	}
	return nil
}

// Save stores or updates an entity in QuicBaaS.
// If the entity's ID is 0, a new ID is generated based on the current timestamp.
func (d *GenericDAO[E]) Save(ctx context.Context, entity E) error {
	if err := d.checkContext(ctx, "Save"); err != nil {
		return err
	}

	// Assign ID if not set (using timestamp as in the original storage implementation)
	if entity.EntityID() == 0 {
		entity.SetEntityID(uint64(time.Now().UnixNano()))
	}

	// Serialize entity to JSON
	data, err := json.Marshal(entity)
	if err != nil {
		return ErrSerializationFailed{EntityType: d.entityType, Cause: err}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if err := d.storage.Put(ctx, d.entityType, entity.EntityID(), data, d.shardID); err != nil {
		return err
	}

	d.logger.Debug("Entity saved", "type", d.entityType, "id", entity.EntityID(), "shardID", d.shardID)
	return nil
}

// Get retrieves an entity by ID.
func (d *GenericDAO[E]) Get(ctx context.Context, id uint64) (E, error) {
	var zero E

	if err := d.checkContext(ctx, "Get"); err != nil {
		return zero, err
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	data, found, err := d.storage.Get(ctx, d.entityType, id, d.shardID)
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

// Delete removes an entity from QuicBaaS.
func (d *GenericDAO[E]) Delete(ctx context.Context, entity E) error {
	if err := d.checkContext(ctx, "Delete"); err != nil {
		return err
	}

	id := entity.EntityID()
	if id == 0 {
		return ErrInvalidEntityID{EntityType: d.entityType, Reason: "cannot delete entity with ID 0"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if err := d.storage.Delete(ctx, d.entityType, id, d.shardID); err != nil {
		return err
	}

	d.logger.Debug("Entity deleted", "type", d.entityType, "id", id, "shardID", d.shardID)
	return nil
}

// Count returns the total number of entities of this type.
func (d *GenericDAO[E]) Count(ctx context.Context) (int, error) {
	if err := d.checkContext(ctx, "Count"); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, d.entityType, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, err
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Page retrieves a page of entities.
// Note: QuicBaaS's List has a quirk where small pageSize values may not properly
// paginate, so we fetch more items at once and do pagination in memory.
func (d *GenericDAO[E]) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[E], error) {
	result := datastore.PageResult[E]{
		Entities: make([]E, 0, pageQuery.PageSize),
		Page:     pageQuery.Page,
		PageSize: pageQuery.PageSize,
		HasMore:  false,
	}

	if err := d.checkContext(ctx, "Page"); err != nil {
		return result, err
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Calculate offset - we need to skip (page-1) * pageSize items
	toSkip := (pageQuery.Page - 1) * pageQuery.PageSize
	// Use a larger fetch size to work around QuicBaaS's List pagination quirk
	// where small pageSize values don't properly return pagination tokens
	fetchSize := uint64(1000)

	// Collect all entities first
	var allEntities []E
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, d.entityType, fetchSize, pageToken, d.shardID)
		if err != nil {
			return result, err
		}

		for _, svcEntity := range entities {
			entity := d.newEntity()
			if err := json.Unmarshal(svcEntity.Data, entity); err != nil {
				d.logger.Warn("Failed to deserialize entity", "type", d.entityType, "id", svcEntity.ID, "error", err)
				continue
			}
			allEntities = append(allEntities, entity)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	// Apply pagination in memory
	totalItems := len(allEntities)
	result.Total = totalItems

	// Skip items
	if toSkip >= totalItems {
		return result, nil
	}

	// Collect items for this page
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
	if err := d.checkContext(ctx, "ForEachPage"); err != nil {
		return err
	}

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
				// Check for stop iteration signal
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

// ShardID returns the shard ID configured for this DAO.
func (d *GenericDAO[E]) ShardID() uint64 {
	return d.shardID
}

// Partition returns the partition name configured for this DAO.
func (d *GenericDAO[E]) Partition() string {
	return d.partition
}
