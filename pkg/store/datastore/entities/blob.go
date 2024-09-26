package entities

const (
	blob_partition = "blob"
)

type Blob struct {
	ID             uint64      `yaml:"id" json:"id"`
	Bytes          []byte      `yaml:"bytes" json:"bytes"`
	Entity         interface{} `yaml:"entity" json:"entity"`
	partition      string      `yaml:"-" json:"-"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewBlob(id uint64, bytes []byte) *Blob {
	return &Blob{
		ID:        id,
		Bytes:     bytes,
		partition: blob_partition,
	}
}

func CreateBlob(id uint64, bytes []byte, partition string) *Blob {
	return &Blob{
		ID:        id,
		Bytes:     bytes,
		partition: partition,
	}
}

func (blob *Blob) SetEntityID(id uint64) {
	blob.ID = id
}

func (blob *Blob) EntityID() uint64 {
	return blob.ID
}

func (blob *Blob) SetEntity(entity interface{}) {
	blob.Entity = entity
}

func (blob *Blob) SetPartition(partition string) {
	blob.partition = partition
}

func (blob *Blob) Partition() string {
	return blob.partition
}
