package keystores

import (
	"context"
	"errors"
)

var (
	ErrOperationNotSupportedByProvider = errors.New("operation not supported by keystore provider")
	ErrOperationNotSupportedByKeyStore = errors.New("operation not supported by keystore")
	ErrOperationNotSupportedByKeyPair  = errors.New("operation not supported by keypair")
)

type KeyStore interface {
	Open() error
	Close() error
	SupportedPrivateKeyAlgorithms() []KeyAlgorithm
	KeyPairs() []KeyPair
	CreateKeyPair(privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
	ImportKeyPair(der []byte) (kp KeyPair, err error)
}

type AsyncKeyStore interface {
	AsyncCreateKeyPair(ctx context.Context, privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
}
