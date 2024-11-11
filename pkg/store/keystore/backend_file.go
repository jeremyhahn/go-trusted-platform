package keystore

import (
	"errors"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/spf13/afero"
)

var (
	ErrFileAlreadyExists = errors.New("store/keystore: file already exists")
	ErrFileNotFound      = errors.New("store/keystore: file not found")

	Partitions = []Partition{
		PARTITION_ROOT,
		PARTITION_TLS,
		PARTITION_HMAC,
		PARTITION_SECRETS,
		PARTITION_ENCRYPTION_KEYS,
		PARTITION_SIGNING_KEYS,
	}
)

type KeyBackend interface {
	Get(attrs *KeyAttributes, extension FSExtension) ([]byte, error)
	Save(attrs *KeyAttributes, data []byte, extension FSExtension, overwrite bool) error
	Delete(attrs *KeyAttributes) error
}

type FileBackend struct {
	logger          *logging.Logger
	fs              afero.Fs
	rootDir         string
	partitionDirMap map[Partition]string
	keyPartitionMap map[KeyType]Partition
	keyExtensions   map[FSExtension]bool
	KeyBackend
}

func NewFileBackend(
	logger *logging.Logger,
	fs afero.Fs,
	rootDir string) KeyBackend {

	// Provides O(1) constant time access to key paritions
	keyPartitionMap := make(map[KeyType]Partition, len(Partitions))
	keyPartitionMap[KEY_TYPE_ATTESTATION] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_CA] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_ENCRYPTION] = PARTITION_ENCRYPTION_KEYS
	keyPartitionMap[KEY_TYPE_ENDORSEMENT] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_HMAC] = PARTITION_HMAC
	keyPartitionMap[KEY_TYPE_IDEVID] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_TPM] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_SECRET] = PARTITION_SECRETS
	keyPartitionMap[KEY_TYPE_SIGNING] = PARTITION_SIGNING_KEYS
	keyPartitionMap[KEY_TYPE_STORAGE] = PARTITION_ROOT
	keyPartitionMap[KEY_TYPE_TLS] = PARTITION_TLS

	// Provides O(1) constant time access to key file extensions
	keyExtensions := make(map[FSExtension]bool, 10)
	keyExtensions[FSEXT_PRIVATE_PKCS8] = true
	keyExtensions[FSEXT_PRIVATE_PKCS8_PEM] = true
	keyExtensions[FSEXT_PUBLIC_PKCS1] = true
	keyExtensions[FSEXT_PUBLIC_PEM] = true
	keyExtensions[FSEXT_PRIVATE_BLOB] = true
	keyExtensions[FSEXT_PUBLIC_BLOB] = true

	// Create the partition map that stores the file system partition paths
	partitionDirMap := make(map[Partition]string, len(Partitions))
	for _, partition := range Partitions {
		dir := fmt.Sprintf("%s/%s", rootDir, partition)
		if err := fs.MkdirAll(dir, os.ModePerm); err != nil {
			panic(err)
		}
		if partition == PARTITION_ROOT {
			partitionDirMap[partition] = rootDir
		} else {
			partitionDirMap[partition] = fmt.Sprintf("%s/%s", rootDir, partition)
		}
	}

	return &FileBackend{
		logger:          logger,
		fs:              fs,
		rootDir:         rootDir,
		partitionDirMap: partitionDirMap,
		keyPartitionMap: keyPartitionMap,
		keyExtensions:   keyExtensions}
}

// Saves the provided data to the file system
func (fb *FileBackend) Save(
	attrs *KeyAttributes,
	data []byte,
	extension FSExtension,
	overwrite bool) error {

	file, err := fb.fileNameFromKeyAttributes(attrs, extension)
	if err != nil {
		fb.logger.Errorf("%s: %s", err, file)
		return err
	}
	if overwrite {
		if err = afero.WriteFile(fb.fs, file, data, 0644); err != nil {
			fb.logger.Errorf("%s: %s", err, file)
			return err
		}
		return nil
	}
	if _, err := fb.fs.Stat(file); errors.Is(err, os.ErrNotExist) {
		if err = afero.WriteFile(fb.fs, file, data, 0644); err != nil {
			fb.logger.Errorf("%s: %s", err, file)
			return err
		}
		return nil
	}
	return fmt.Errorf("%s: %s", ErrFileAlreadyExists, file)
}

// Retrieves the requested data
func (fb *FileBackend) Get(
	attrs *KeyAttributes,
	extension FSExtension) ([]byte, error) {

	file, err := fb.fileNameFromKeyAttributes(attrs, extension)
	if err != nil {
		fb.logger.Errorf("%s: %s", err, file)
		return nil, err
	}
	bytes, err := afero.ReadFile(fb.fs, file)
	if err != nil {
		if os.IsNotExist(err) {
			fb.logger.Warnf("%s: %s", ErrFileNotFound, file)
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Retrieves the requested data
func (fb *FileBackend) Delete(attrs *KeyAttributes) error {
	partitionDir, err := fb.partitionKey(attrs)
	if err != nil {
		fb.logger.Errorf("%s: %s", err, attrs.CN)
		return err
	}
	if err := fb.fs.RemoveAll(partitionDir); err != nil {
		fb.logger.Errorf("%s: %s", err, partitionDir)
		return err
	}
	// Delete passwords / HMACS
	hmacAttrs := *attrs
	hmacAttrs.KeyType = KEY_TYPE_HMAC
	partitionDir, err = fb.partitionKey(&hmacAttrs)
	if err != nil {
		return err
	}
	if err := fb.fs.RemoveAll(partitionDir); err != nil {
		fb.logger.Errorf("%s: %s", err, partitionDir)
		return err
	}
	return nil
}

// Returns a partition path for the given key attributes and partition type
func (fb *FileBackend) partitionKey(attrs *KeyAttributes) (string, error) {

	var ok bool
	var cnDir, partitionDir string

	keyPartition, ok := fb.keyPartitionMap[attrs.KeyType]
	if !ok {
		fb.logger.Errorf("%s: %s", ErrInvalidKeyType, attrs.CN)
		return "", ErrInvalidKeyType
	}

	partitionDir, ok = fb.partitionDirMap[keyPartition]
	if !ok {
		fb.logger.Errorf("%s: %s", ErrInvalidKeyPartition, attrs.CN)
		return "", ErrInvalidKeyPartition
	}

	if attrs.KeyType == KEY_TYPE_CA || attrs.KeyType == KEY_TYPE_TPM {
		return partitionDir, nil
	}

	cnDir = fmt.Sprintf("%s/%s", partitionDir, attrs.CN)
	if err := fb.fs.MkdirAll(cnDir, os.ModePerm); err != nil {
		fb.logger.Errorf("%s: %s", err, cnDir)
		return "", err
	}

	return cnDir, nil
}

// Returns a file name given key attributes and a file extension
func (fb *FileBackend) fileNameFromKeyAttributes(
	attrs *KeyAttributes,
	extension FSExtension) (string, error) {

	// Get the file partition
	partitionDir, err := fb.partitionKey(attrs)
	if err != nil {
		fb.logger.Errorf("%s: %s", err, partitionDir)
		return "", err
	}

	// Create a file extension with the key type (rsa, ecdsa, ed25519)
	ext := KeyFileExtension(attrs.KeyAlgorithm, extension, &attrs.KeyType)

	// Create the final file name
	file := fmt.Sprintf("%s/%s.%s%s",
		partitionDir, attrs.CN, attrs.StoreType, ext)

	return file, nil
}
