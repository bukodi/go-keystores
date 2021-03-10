package keystores

import (
	"context"
	"errors"
)

var (
	ErrOperationNotSupportedByProvider = errors.New("operation not supported by keystore provider")
	ErrProviderAlreadyOpen             = errors.New("provider already open")
	ErrProviderAlreadyClosed           = errors.New("provider already closed")
)

type Provider interface {
	KeyStores() ([]KeyStore, []error)
	Open() error
	Close() error
}

type DynamicProvider interface {
	Provider
	OnConnected(handler func(store KeyStore) error)
	OnDisconnected(handler func(store KeyStore) error)
}

type AsyncProvider interface {
	AsyncKeyStores(ctx context.Context) (chan KeyStore, chan error)
}
