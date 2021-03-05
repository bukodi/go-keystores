package keystores

import "context"

type Provider interface {
	KeyStores() ([]*KeyStore, error)
	Open() error
	Close() error
}

type DynamicProvider interface {
	Provider
	OnConnected(handler func(store *KeyStore) error)
	OnDisconnected(handler func(store *KeyStore) error)
}

type AsyncProvider interface {
	AsyncKeyStores(ctx context.Context) (chan *KeyStore, chan error)
}
