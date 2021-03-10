package pkcs11ks

import (
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11KeyStore struct {
	provider  *Pkcs11Provider
	slotId    uint
	tokenInfo *p11api.TokenInfo
	slotInfo  *p11api.SlotInfo
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &Pkcs11KeyStore{}

func (ks *Pkcs11KeyStore) Id() string {
	return ks.tokenInfo.SerialNumber
}

func (ks *Pkcs11KeyStore) Name() string {
	return ks.tokenInfo.Label
}

func (ks *Pkcs11KeyStore) Open() error {
	panic("implement me")
}

func (ks *Pkcs11KeyStore) Close() error {
	panic("implement me")
}

func (ks *Pkcs11KeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{keystores.KeyAlgRSA2048, keystores.KeyAlgECP256}
	return algs
}

func (ks *Pkcs11KeyStore) KeyPairs() []keystores.KeyPair {
	panic("implement me")
}

func (ks *Pkcs11KeyStore) CreateKeyPair(privateKeyAlgorithm keystores.KeyAlgorithm, opts interface{}) (kp keystores.KeyPair, err error) {
	panic("implement me")
}

func (ks *Pkcs11KeyStore) ImportKeyPair(der []byte) (kp keystores.KeyPair, err error) {
	panic("implement me")
}
