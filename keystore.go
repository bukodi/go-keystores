package keystores

import (
	"context"
	"errors"
)

var (
	ErrOperationNotSupportedByKeyStore = errors.New("operation not supported by key store")
)

type KeyStore interface {
	// Unique identifier within the provider. The returned Id must be URL safe.
	Id() string
	Name() string
	Open() error
	Close() error
	IsOpen() bool
	SupportedPrivateKeyAlgorithms() []KeyAlgorithm
	KeyPairs() []KeyPair // TODO add return []error
	CreateKeyPair(opts GenKeyPairOpts) (kp KeyPair, err error)
	ImportKeyPair(der []byte) (kp KeyPair, err error)
}

type AsyncKeyStore interface {
	AsyncCreateKeyPair(ctx context.Context, privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
}
