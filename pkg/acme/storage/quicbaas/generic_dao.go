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
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
)

// defaultTargetBackend is the QuicBaaS objectstorage backend name.
// Must match the backend registered with the embedded server (typically "default").
const defaultTargetBackend = "default"

// genericDAO implements qrdbsdk.GenericDAO backed by QuicBaaS ObjectStorage.
// It provides a single generic implementation that works for all ACME entity types,
// using reflection-based field lookups for index queries.
type genericDAO[E qrdbsdk.Entity] struct {
	storage    objectstorage.Client
	keyPrefix  string
	tenantID   string
	newEntity  func() E
	entityType string
}

// Compile-time interface check.
var _ qrdbsdk.GenericDAO[*verifyEntity] = (*genericDAO[*verifyEntity])(nil)

// verifyEntity is used only for the compile-time interface check above.
type verifyEntity struct {
	ID uint64
}

func (e *verifyEntity) EntityID() uint64      { return e.ID }
func (e *verifyEntity) SetEntityID(id uint64) { e.ID = id }

// newGenericDAO creates a new genericDAO backed by the given ObjectStorage client.
func newGenericDAO[E qrdbsdk.Entity](
	stor objectstorage.Client,
	keyPrefix string,
	tenantID string,
	newEntity func() E,
	entityType string,
) *genericDAO[E] {
	return &genericDAO[E]{
		storage:    stor,
		keyPrefix:  keyPrefix,
		tenantID:   tenantID,
		newEntity:  newEntity,
		entityType: entityType,
	}
}

// makeKey creates a storage key for an entity ID.
func (d *genericDAO[E]) makeKey(id uint64) string {
	return d.keyPrefix + "/" + strconv.FormatUint(id, 10)
}

// Save persists an entity to storage.
func (d *genericDAO[E]) Save(ctx context.Context, entity E) error {
	id := entity.EntityID()
	if id == 0 {
		return qrdbsdk.DAOInvalidEntityIDError{
			EntityType: d.entityType,
			Reason:     "entity ID must be non-zero",
		}
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return qrdbsdk.DAOSerializationFailedError{
			EntityType: d.entityType,
			Cause:      err,
		}
	}

	key := d.makeKey(id)
	_, putErr := d.storage.PutObject(ctx, &objectstorage.PutObjectRequest{
		Key:           key,
		Value:         data,
		ContentType:   "application/json",
		TenantID:      d.tenantID,
		TargetBackend: defaultTargetBackend,
		Tags: map[string]string{
			"entity_type": d.entityType,
			"entity_id":   strconv.FormatUint(id, 10),
		},
	})
	if putErr != nil {
		return StorageOperationError{
			Op:         "put",
			EntityType: d.entityType,
			Key:        key,
			Cause:      putErr,
		}
	}

	return nil
}

// SaveWithCondition persists an entity only if the condition is satisfied
// against the existing entity.
func (d *genericDAO[E]) SaveWithCondition(ctx context.Context, entity E, cond qrdbsdk.Condition) error {
	id := entity.EntityID()
	if id == 0 {
		return qrdbsdk.DAOInvalidEntityIDError{
			EntityType: d.entityType,
			Reason:     "entity ID must be non-zero",
		}
	}

	existing, err := d.Get(ctx, id)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return d.Save(ctx, entity)
		}
		return err
	}

	if !evaluateCondition(existing, cond) {
		return qrdbsdk.DAOConditionFailedError{
			Condition: cond,
			Reason:    "condition not satisfied for existing entity",
		}
	}

	return d.Save(ctx, entity)
}

// Get retrieves an entity by ID.
func (d *genericDAO[E]) Get(ctx context.Context, id uint64) (E, error) {
	var zero E

	key := d.makeKey(id)
	resp, err := d.storage.GetObject(ctx, &objectstorage.GetObjectRequest{
		Key:      key,
		TenantID: d.tenantID,
	})
	if err != nil {
		if isNotFoundErr(err) {
			return zero, qrdbsdk.DAONotFoundError{
				EntityType: d.entityType,
				ID:         id,
			}
		}
		return zero, StorageOperationError{
			Op:         "get",
			EntityType: d.entityType,
			Key:        key,
			Cause:      err,
		}
	}

	entity := d.newEntity()
	if unmarshalErr := json.Unmarshal(resp.Value, entity); unmarshalErr != nil {
		return zero, qrdbsdk.DAODeserializationFailedError{
			EntityType: d.entityType,
			Cause:      unmarshalErr,
		}
	}

	return entity, nil
}

// Delete removes an entity from storage.
func (d *genericDAO[E]) Delete(ctx context.Context, entity E) error {
	id := entity.EntityID()
	if id == 0 {
		return qrdbsdk.DAOInvalidEntityIDError{
			EntityType: d.entityType,
			Reason:     "entity ID must be non-zero",
		}
	}

	key := d.makeKey(id)
	_, err := d.storage.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{
		Key:      key,
		TenantID: d.tenantID,
	})
	if err != nil {
		if isNotFoundErr(err) {
			// Delete is idempotent per the GenericDAO contract.
			return nil
		}
		return StorageOperationError{
			Op:         "delete",
			EntityType: d.entityType,
			Key:        key,
			Cause:      err,
		}
	}

	return nil
}

// Count returns the total number of entities.
func (d *genericDAO[E]) Count(ctx context.Context) (int, error) {
	keys, err := d.listEntityKeys(ctx)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// Page retrieves a single page of entities.
func (d *genericDAO[E]) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[E], error) {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return qrdbsdk.PageResult[E]{}, err
	}

	sortEntities(entities, query)

	return paginate(entities, query), nil
}

// ForEachPage iterates over all entities page by page.
func (d *genericDAO[E]) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[E]) error {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return err
	}

	sortEntities(entities, query)

	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	total := len(entities)
	for offset := 0; offset < total; offset += pageSize {
		end := offset + pageSize
		if end > total {
			end = total
		}

		result := qrdbsdk.PageResult[E]{
			Entities: entities[offset:end],
			Page:     (offset / pageSize) + 1,
			PageSize: pageSize,
			Total:    total,
			HasMore:  end < total,
		}

		if callbackErr := fn(result); callbackErr != nil {
			if callbackErr == qrdbsdk.ErrDAOStopIteration {
				return nil
			}
			return callbackErr
		}
	}

	return nil
}

// EntityType returns the entity type name.
func (d *genericDAO[E]) EntityType() string {
	return d.entityType
}

// QueryByIndex returns all entities matching the given field value.
// Uses reflection-based full scan.
func (d *genericDAO[E]) QueryByIndex(ctx context.Context, fieldName string, value interface{}) ([]E, error) {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	var results []E
	for _, entity := range entities {
		if fieldMatches(entity, fieldName, value) {
			results = append(results, entity)
		}
	}

	return results, nil
}

// QueryOneByIndex returns a single entity matching the given field value.
func (d *genericDAO[E]) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (E, error) {
	var zero E

	entities, err := d.QueryByIndex(ctx, fieldName, value)
	if err != nil {
		return zero, err
	}

	if len(entities) == 0 {
		return zero, qrdbsdk.DAONotFoundError{
			EntityType: d.entityType,
			ID:         0,
		}
	}

	return entities[0], nil
}

// ScanByIndex returns all entities with field values in the range [start, end).
// Uses reflection-based full scan with string comparison of field values.
func (d *genericDAO[E]) ScanByIndex(ctx context.Context, fieldName string, start, end interface{}) ([]E, error) {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	startStr := fmt.Sprintf("%v", start)
	endStr := fmt.Sprintf("%v", end)

	var results []E
	for _, entity := range entities {
		fv := fieldValue(entity, fieldName)
		if fv == "" {
			continue
		}
		if fv >= startStr && fv < endStr {
			results = append(results, entity)
		}
	}

	return results, nil
}

// PageByIndex returns a page of entities matching the given index field value.
func (d *genericDAO[E]) PageByIndex(ctx context.Context, fieldName string, value interface{}, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[E], error) {
	entities, err := d.QueryByIndex(ctx, fieldName, value)
	if err != nil {
		return qrdbsdk.PageResult[E]{}, err
	}

	sortEntities(entities, query)

	return paginate(entities, query), nil
}

// CountByIndex returns the count of entities matching the given index value.
func (d *genericDAO[E]) CountByIndex(ctx context.Context, fieldName string, value interface{}) (int, error) {
	entities, err := d.QueryByIndex(ctx, fieldName, value)
	if err != nil {
		return 0, err
	}
	return len(entities), nil
}

// QueryByCompoundIndex returns all entities matching multiple field values.
// Uses reflection-based full scan, checking all field-value pairs.
func (d *genericDAO[E]) QueryByCompoundIndex(ctx context.Context, indexName string, fieldValues []interface{}) ([]E, error) {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	// Parse the compound index name to get field names.
	// Convention: index name is "field1+field2+field3"
	fieldNames := strings.Split(indexName, "+")
	if len(fieldNames) != len(fieldValues) {
		return nil, fmt.Errorf("compound index %s expects %d fields, got %d values",
			indexName, len(fieldNames), len(fieldValues))
	}

	var results []E
	for _, entity := range entities {
		match := true
		for i, fname := range fieldNames {
			if !fieldMatches(entity, fname, fieldValues[i]) {
				match = false
				break
			}
		}
		if match {
			results = append(results, entity)
		}
	}

	return results, nil
}

// ScanByCompoundIndex returns entities matching a prefix of compound index
// field values with a range scan on the remaining field.
func (d *genericDAO[E]) ScanByCompoundIndex(ctx context.Context, indexName string, prefixValues []interface{}, rangeStart, rangeEnd interface{}) ([]E, error) {
	entities, err := d.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	fieldNames := strings.Split(indexName, "+")
	if len(prefixValues) >= len(fieldNames) {
		return nil, fmt.Errorf("compound index %s: prefix values must be fewer than total fields", indexName)
	}

	var results []E
	for _, entity := range entities {
		match := true
		for i, fname := range fieldNames[:len(prefixValues)] {
			if !fieldMatches(entity, fname, prefixValues[i]) {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		if len(prefixValues) < len(fieldNames) {
			rangeField := fieldNames[len(prefixValues)]
			fv := fieldValue(entity, rangeField)
			startStr := fmt.Sprintf("%v", rangeStart)
			endStr := fmt.Sprintf("%v", rangeEnd)
			if fv < startStr || fv >= endStr {
				continue
			}
		}

		results = append(results, entity)
	}

	return results, nil
}

// Find returns nil because QueryBuilder is a qrdb-specific type tightly
// coupled to qrdb's internal genericDAO. Advanced query building is not
// supported by the ObjectStorage backend.
func (d *genericDAO[E]) Find(ctx context.Context) *qrdbsdk.QueryBuilder[E] {
	return nil
}

// listEntityKeys returns all storage keys under this DAO's prefix.
func (d *genericDAO[E]) listEntityKeys(ctx context.Context) ([]string, error) {
	resp, err := d.storage.ListObjects(ctx, &objectstorage.ListObjectsRequest{
		Prefix:   d.keyPrefix + "/",
		TenantID: d.tenantID,
	})
	if err != nil {
		return nil, ListOperationError{
			EntityType: d.entityType,
			Prefix:     d.keyPrefix,
			Cause:      err,
		}
	}

	var entityKeys []string
	for _, obj := range resp.Objects {
		suffix := strings.TrimPrefix(obj.Key, d.keyPrefix+"/")
		// Only include keys that are direct children (no further slashes).
		if suffix != obj.Key && !strings.Contains(suffix, "/") && suffix != "" {
			entityKeys = append(entityKeys, obj.Key)
		}
	}

	return entityKeys, nil
}

// loadAll loads all entities under this DAO's prefix.
func (d *genericDAO[E]) loadAll(ctx context.Context) ([]E, error) {
	keys, err := d.listEntityKeys(ctx)
	if err != nil {
		return nil, err
	}

	entities := make([]E, 0, len(keys))
	for _, key := range keys {
		suffix := strings.TrimPrefix(key, d.keyPrefix+"/")
		id, parseErr := strconv.ParseUint(suffix, 10, 64)
		if parseErr != nil {
			continue
		}

		entity, getErr := d.Get(ctx, id)
		if getErr != nil {
			if qrdbsdk.IsDAONotFound(getErr) {
				continue
			}
			return nil, getErr
		}

		entities = append(entities, entity)
	}

	return entities, nil
}

// paginate applies pagination to a slice of entities.
func paginate[E qrdbsdk.Entity](entities []E, query qrdbsdk.PageQuery) qrdbsdk.PageResult[E] {
	total := len(entities)
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	offset := (page - 1) * pageSize
	if offset >= total {
		return qrdbsdk.PageResult[E]{
			Entities: nil,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
			HasMore:  false,
		}
	}

	end := offset + pageSize
	if end > total {
		end = total
	}

	return qrdbsdk.PageResult[E]{
		Entities: entities[offset:end],
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		HasMore:  end < total,
	}
}

// sortEntities sorts entities by ID (ascending or descending based on SortOrder).
func sortEntities[E qrdbsdk.Entity](entities []E, query qrdbsdk.PageQuery) {
	sort.Slice(entities, func(i, j int) bool {
		if query.SortOrder < 0 {
			return entities[i].EntityID() > entities[j].EntityID()
		}
		return entities[i].EntityID() < entities[j].EntityID()
	})
}

// fieldMatches checks if an entity's field matches the expected value using reflection.
func fieldMatches(entity interface{}, fieldName string, expected interface{}) bool {
	val := reflect.ValueOf(entity)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return false
		}
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return false
	}

	field := val.FieldByName(fieldName)
	if !field.IsValid() {
		return false
	}

	return reflect.DeepEqual(field.Interface(), expected)
}

// fieldValue returns the string representation of a struct field value.
func fieldValue(entity interface{}, fieldName string) string {
	val := reflect.ValueOf(entity)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return ""
		}
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return ""
	}

	field := val.FieldByName(fieldName)
	if !field.IsValid() {
		return ""
	}

	return fmt.Sprintf("%v", field.Interface())
}

// evaluateCondition evaluates a qrdbsdk.Condition against an existing entity.
func evaluateCondition(entity interface{}, cond qrdbsdk.Condition) bool {
	switch cond.Target {
	case qrdbsdk.ConditionValue:
		return reflect.DeepEqual(entity, cond.Value)
	default:
		// Version/timestamp conditions are not tracked by ObjectStorage.
		return true
	}
}

// isNotFoundErr checks if an error indicates a not-found condition.
// It checks both the error message string patterns used by QuicBaaS
// and the qrdb not-found error type.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	if qrdbsdk.IsDAONotFound(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "no such")
}
