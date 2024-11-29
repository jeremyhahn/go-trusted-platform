package entities

type KeyValueEntity interface {
	SetEntityID(id uint64)
	EntityID() uint64
}

type Index interface {
	Name() string
	RefID() uint64
	KeyValueEntity
}

type TimeSeriesIndexer interface {
	KeyValueEntity
	SetTimestamp(timestamp uint64)
	Timestamp() uint64
}
