package keystores

import (
	"context"
	"crypto"
	"errors"
)

var (
	ErrNotImplemented                  = errors.New("not implemented yet")
	ErrAlgorithmNotSupportedByKeyStore = errors.New("algorithm not supported by key store")
	ErrOperationNotSupportedByKeyStore = errors.New("operation not supported by key store")
)

type KeyStore interface {
	// Unique identifier within the provider. The returned Id must be URL safe.
	Id() string
	Name() string
	Open() error
	Close() error
	IsOpen() bool
	Reload() error
	SupportedPrivateKeyAlgorithms() []KeyAlgorithm
	KeyPairById(id KeyPairId) KeyPair
	KeyPairs(reload bool) (map[KeyPairId]KeyPair, error)
	CreateKeyPair(opts GenKeyPairOpts) (kp KeyPair, err error)
	ImportKeyPair(privKey crypto.PrivateKey, opts GenKeyPairOpts) (kp KeyPair, err error)
}

type AsyncKeyStore interface {
	Id(ctx context.Context) <-chan string
	Name(ctx context.Context) <-chan string
	Open(ctx context.Context) <-chan error
	Close(ctx context.Context) <-chan error
	IsOpen(ctx context.Context) <-chan bool
	Reload(ctx context.Context) <-chan error
	SupportedPrivateKeyAlgorithms(ctx context.Context) <-chan KeyAlgorithm
	KeyPairs(ctx context.Context) (<-chan AsyncKeyPair, <-chan error)
	CreateKeyPair(ctx context.Context, opts GenKeyPairOpts) (<-chan AsyncKeyPair, <-chan error)
	ImportKeyPair(ctx context.Context, der []byte) (<-chan AsyncKeyPair, <-chan error)
}
