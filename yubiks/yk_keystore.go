package yubiks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/go-piv/piv-go/piv"
)

type YkKeyStore struct {
	provider *YkProvider
	pivyk    *piv.YubiKey
	serial   string
	cardName string
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &YkKeyStore{}

func (ks *YkKeyStore) Id() string {
	return ks.serial
}

func (ks *YkKeyStore) Name() string {
	return fmt.Sprintf("%s (#%s)", ks.cardName, ks.serial)
}

func (ks *YkKeyStore) Open() error {
	return nil
}

func (ks *YkKeyStore) Close() error {
	return nil
}

func (ks *YkKeyStore) IsOpen() bool {
	return true
}

func (ks *YkKeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{keystores.KeyAlgRSA2048, keystores.KeyAlgECP256}
	return algs
}

func (ks *YkKeyStore) KeyPairs() (kpArray []keystores.KeyPair, errs []error) {
	panic("implement me")
}

func (ks *YkKeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	panic("implement me")
}

func (ks *YkKeyStore) ImportKeyPair(der []byte) (kp keystores.KeyPair, err error) {
	panic("implement me")
}
