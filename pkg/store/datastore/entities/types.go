package entities

type KeyValueEntity interface {
	SetEntityID(id uint64)
	EntityID() uint64
	Partition() string
}

type TimeSeriesIndexer interface {
	KeyValueEntity
	SetTimestamp(timestamp uint64)
	Timestamp() uint64
}
