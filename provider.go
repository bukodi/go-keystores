package keystores

import (
	"context"
	"errors"
)

var (
	ErrOperationNotSupportedByProvider = errors.New("operation not supported by keystore provider")
)

type Provider interface {
	KeyStores() ([]KeyStore, error)
	Open() error
	Close() error
	IsOpen() bool
}

type DynamicProvider interface {
	Provider
	OnConnected(handler func(store KeyStore) error)
	OnDisconnected(handler func(store KeyStore) error)
}

type AsyncProvider interface {
	OpenAsync(ctx context.Context, onKs func(store KeyStore), onErr func(err error)) <-chan struct{}
}
