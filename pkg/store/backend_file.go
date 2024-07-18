package store

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/op/go-logging"
)

var (
	ErrFileAlreadyExists = errors.New("store/backend: file already exists")
	ErrFileNotFound      = errors.New("store/backend: file not found")

	Partitions = []Partition{
		PARTITION_CA,
		PARTITION_TRUSTED_ROOT,
		PARTITION_TRUSTED_INTERMEDIATE,
		PARTITION_TLS,
		PARTITION_REVOKED,
		PARTITION_CRL,
		PARTITION_SIGNED_BLOB,
		PARTITION_ENCRYPTION_KEYS,
		PARTITION_SIGNING_KEYS,
	}

	X509Types = []keystore.X509Type{
		keystore.X509_TYPE_TLS,
		keystore.X509_TYPE_TRUSTED_ROOT,
		keystore.X509_TYPE_TRUSTED_INTERMEDIATE,
	}
)

type Backend interface {
	Append(
		attrs keystore.KeyAttributes,
		data []byte,
		extension FSExtension,
		partition *Partition) error
	Get(
		attrs keystore.KeyAttributes,
		extension FSExtension,
		partition *Partition) ([]byte, error)
	KeyFileExtension(
		algo x509.PublicKeyAlgorithm,
		extension FSExtension) FSExtension
	PartitionKey(
		attrs keystore.KeyAttributes,
		partition *Partition) (string, error)
	Save(
		attrs keystore.KeyAttributes,
		data []byte,
		extension FSExtension,
		partition *Partition) error
}

type FileBackend struct {
	logger           *logging.Logger
	rootDir          string
	partitionDirMap  map[Partition]string
	keyPartitionMap  map[keystore.KeyType]Partition
	keyExtensions    map[FSExtension]bool
	x509PartitionMap map[keystore.X509Type]Partition
	Backend
}

func NewFileBackend(logger *logging.Logger, rootDir string) Backend {

	keyPartitionMap := make(map[keystore.KeyType]Partition, len(Partitions))
	keyPartitionMap[keystore.KEY_TYPE_CA] = PARTITION_CA
	keyPartitionMap[keystore.KEY_TYPE_TLS] = PARTITION_TLS
	keyPartitionMap[keystore.KEY_TYPE_SIGNING] = PARTITION_SIGNING_KEYS
	keyPartitionMap[keystore.KEY_TYPE_ENCRYPTION] = PARTITION_ENCRYPTION_KEYS

	keyExtensions := make(map[FSExtension]bool, 7)
	keyExtensions[FSEXT_PRIVATE_PKCS8] = true
	keyExtensions[FSEXT_PRIVATE_PKCS8_PEM] = true
	keyExtensions[FSEXT_PUBLIC_PKCS1] = true
	keyExtensions[FSEXT_PUBLIC_PEM] = true
	// The following aren't keys, they're certs, but including them
	// here so their file names are generated with the key algorithm
	// too. This is necessary for signing operations which need to
	// locate and use the correct / matching certificate for the key
	// being used to sign the certificate.
	keyExtensions[FSEXT_DER] = true
	keyExtensions[FSEXT_PEM] = true
	keyExtensions[FSEXT_CA_BUNDLE_PEM] = true

	// X509 certificate type to partition type map
	x509PartitionMap := make(map[keystore.X509Type]Partition, len(X509Types))
	x509PartitionMap[keystore.X509_TYPE_LOCAL_ATTESTATION] = PARTITION_SIGNED_BLOB
	x509PartitionMap[keystore.X509_TYPE_REMOTE_ATTESTATION] = PARTITION_TLS
	x509PartitionMap[keystore.X509_TYPE_TLS] = PARTITION_TLS
	x509PartitionMap[keystore.X509_TYPE_TRUSTED_ROOT] = PARTITION_TRUSTED_ROOT
	x509PartitionMap[keystore.X509_TYPE_TRUSTED_INTERMEDIATE] = PARTITION_TRUSTED_INTERMEDIATE

	// Create the partition map that stores the file system partition paths
	partitionDirMap := make(map[Partition]string, len(Partitions))
	for _, partition := range Partitions {
		dir := fmt.Sprintf("%s/%s", rootDir, partition)
		if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
			panic(err)
		}
		if partition == PARTITION_CA {
			partitionDirMap[partition] = rootDir
		} else {
			partitionDirMap[partition] = fmt.Sprintf("%s/%s", rootDir, partition)
		}
	}

	return FileBackend{
		logger:           logger,
		rootDir:          rootDir,
		partitionDirMap:  partitionDirMap,
		keyPartitionMap:  keyPartitionMap,
		keyExtensions:    keyExtensions,
		x509PartitionMap: x509PartitionMap}
}

// Returns a partition path for the given key attributes and partition type
func (fb FileBackend) PartitionKey(
	attrs keystore.KeyAttributes,
	partition *Partition) (string, error) {

	var ok bool
	var cnDir, partitionDir string

	if partition == nil {
		if attrs.X509Attributes != nil && attrs.X509Attributes.Type != 0 {
			// Get the partition based on the x509 attribute type
			x509Partition, ok := fb.x509PartitionMap[attrs.X509Attributes.Type]
			if !ok {
				return "", ErrInvalidKeyPartition
			}
			// Get the partition file system path
			partitionDir, ok = fb.partitionDirMap[x509Partition]
			if !ok {
				return "", ErrInvalidKeyPartition
			}
			switch attrs.X509Attributes.Type {
			case keystore.X509_TYPE_TRUSTED_ROOT, keystore.X509_TYPE_TRUSTED_INTERMEDIATE:
				cnDir = partitionDir
			default:
				// Add the x509 attributes CN to the partition path
				cnDir = fmt.Sprintf("%s/%s", partitionDir, attrs.X509Attributes.CN)
			}
			if err := os.MkdirAll(cnDir, os.ModePerm); err != nil {
				return "", err
			}
			// Return the final path, the rest of the logic in this
			// method is only concerned with keys
			return cnDir, nil
		} else {
			// Use key attributes  to locate the partition
			keyPartition, ok := fb.keyPartitionMap[attrs.KeyType]
			if !ok {
				return "", keystore.ErrInvalidKeyType
			}
			partitionDir, ok = fb.partitionDirMap[keyPartition]
			if !ok {
				return "", ErrInvalidKeyPartition
			}
		}
	} else {
		partitionDir, ok = fb.partitionDirMap[*partition]
		if !ok {
			return "", ErrInvalidKeyPartition
		}
	}

	if attrs.KeyType == keystore.KEY_TYPE_CA || attrs.KeyType == keystore.KEY_TYPE_NULL {
		return partitionDir, nil
	}

	cnDir = fmt.Sprintf("%s/%s", partitionDir, attrs.CN)
	if err := os.MkdirAll(cnDir, os.ModePerm); err != nil {
		return "", err
	}

	return cnDir, nil
}

// Prefix key algorith name to file extension
func (fb FileBackend) KeyFileExtension(algo x509.PublicKeyAlgorithm, extension FSExtension) FSExtension {
	keyExt := FSEXTKeyAlgorithm(algo)
	return FSExtension(fmt.Sprintf("%s%s", keyExt, extension))
}

// Returns a file name given key attributes and a file extension
func (fb FileBackend) fileNameFromKeyAttributes(
	attrs keystore.KeyAttributes,
	extension FSExtension,
	partition *Partition) (string, error) {

	// Get the file partition
	partitionDir, err := fb.PartitionKey(attrs, partition)
	if err != nil {
		return "", err
	}

	if attrs.X509Attributes != nil {
		// These key attributes belong to an X509 certificate.
		// Return the partition using the x509 certificate type
		// and common name as sub directories
		extension = fb.KeyFileExtension(attrs.KeyAlgorithm, extension)
		var file string
		if attrs.X509Attributes.Type == keystore.X509_TYPE_REMOTE_ATTESTATION {
			file = fmt.Sprintf("%s/%s%s", partitionDir, attrs.CN, extension)
		} else {
			file = fmt.Sprintf("%s/%s%s", partitionDir, attrs.X509Attributes.CN, extension)
		}
		return file, nil
	}

	// This is a key - build the file path based on the key type

	// Use key extension unless key type is null
	if attrs.KeyType != keystore.KEY_TYPE_NULL {
		_, ok := fb.keyExtensions[extension]
		if ok {
			extension = fb.KeyFileExtension(attrs.KeyAlgorithm, extension)
		}
	}

	var file string
	switch attrs.KeyType {
	case keystore.KEY_TYPE_NULL, keystore.KEY_TYPE_CA:

		// Partition is the CA root directory
		file = fmt.Sprintf("%s/%s%s", partitionDir, attrs.Domain, extension)

	default:
		// Partition uses the CN as a sub directory
		file = fmt.Sprintf("%s/%s%s", partitionDir, attrs.CN, extension)
	}

	return file, nil
}

// Saves the provided data to the backend
func (fb FileBackend) Save(
	attrs keystore.KeyAttributes,
	data []byte,
	extension FSExtension,
	partition *Partition) error {

	file, err := fb.fileNameFromKeyAttributes(attrs, extension, partition)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(file, data, 0644); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("%s: %s", ErrFileAlreadyExists, file)
}

// Retrieves the data
func (fb FileBackend) Get(
	attrs keystore.KeyAttributes,
	extension FSExtension,
	partition *Partition) ([]byte, error) {

	file, err := fb.fileNameFromKeyAttributes(attrs, extension, partition)
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			fb.logger.Errorf("%s: %s", ErrFileNotFound, file)
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Appends certificate bytes to an existing certificate file
func (fb FileBackend) Append(
	attrs keystore.KeyAttributes,
	data []byte,
	extension FSExtension,
	partition *Partition) error {

	file, err := fb.fileNameFromKeyAttributes(attrs, extension, partition)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return nil
}
