package asyncks

import (
	"context"
	"github.com/bukodi/go-keystores"
)

func CreateSyncKeyStore(ctx context.Context, asyncKs keystores.AsyncKeyStore) keystores.KeyStore {
	syncKs := syncKs{
		ctx:     ctx,
		asyncKs: asyncKs,
	}
	return &syncKs
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &syncKs{}

type syncKs struct {
	ctx     context.Context
	asyncKs keystores.AsyncKeyStore
}

func (s syncKs) Id() string {
	ctx, _ := context.WithCancel(s.ctx)
	idCh := s.asyncKs.Id(ctx)
	select {
	case <-ctx.Done():
		return ""
	case id, ok := <-idCh:
		if !ok {
			return ""
		} else {
			return id
		}
	default:
	}
	return ""
}

func (s syncKs) Name() string {
	panic("implement me")
}

func (s syncKs) Open() error {
	panic("implement me")
}

func (s syncKs) Close() error {
	panic("implement me")
}

func (s syncKs) IsOpen() bool {
	panic("implement me")
}

func (s syncKs) Reload() error {
	panic("implement me")
}

func (s syncKs) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	panic("implement me")
}

func (s syncKs) KeyPairs() ([]keystores.KeyPair, error) {
	panic("implement me")
}

func (s syncKs) CreateKeyPair(opts keystores.GenKeyPairOpts) (kp keystores.KeyPair, err error) {
	panic("implement me")
}

func (s syncKs) ImportKeyPair(der []byte) (kp keystores.KeyPair, err error) {
	panic("implement me")
}
