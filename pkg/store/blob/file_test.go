package blob

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
)

func expectedPathBlob(cn []byte) string {
	return fmt.Sprintf("%s/blobs%s", TEST_TMP_DIR, cn)
}

func TestSaveAndGetBlob(t *testing.T) {

	data := []byte("test")

	store := defaultStore()

	blobKey := []byte("/test/path.txt")

	err := store.Save(blobKey, data)
	assert.Nil(t, err)

	persisted, err := store.Get(blobKey)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathBlob(blobKey)

	path := util.FileExists(expectedPath)
	assert.True(t, path)
}
