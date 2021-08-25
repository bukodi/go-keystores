package inmemoryks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/bukodi/go-keystores"
	"unsafe"
)

// TODO: Use https://github.com/awnumar/memguard
type InMemoryKeyStore struct {
	keyPairs []*InMemoryKeyPair
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &InMemoryKeyStore{}

func (imks *InMemoryKeyStore) Id() string {
	ptr := uintptr(unsafe.Pointer(imks))
	return fmt.Sprintf("%v", ptr)
}

func (imks *InMemoryKeyStore) Name() string {
	return "In memory key store"
}

func (imks *InMemoryKeyStore) Open() error {
	return keystores.ErrorHandler(keystores.ErrAlreadyOpen, imks)
}

func (imks *InMemoryKeyStore) Close() error {
	return keystores.ErrorHandler(keystores.ErrOperationNotSupportedByKeyStore, imks)
}

func (imks *InMemoryKeyStore) IsOpen() bool {
	return true
}

func (imks *InMemoryKeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{keystores.KeyAlgRSA2048, keystores.KeyAlgECP256}
	return algs
}

func (imks *InMemoryKeyStore) KeyPairs() ([]keystores.KeyPair, []error) {
	if imks.keyPairs == nil {
		return make([]keystores.KeyPair, 0), nil
	}
	ret := make([]keystores.KeyPair, len(imks.keyPairs))
	for i, kp := range imks.keyPairs {
		ret[i] = kp
	}
	return ret, nil
}

func (imks *InMemoryKeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {

	imkp := InMemoryKeyPair{
		keySore:     imks,
		keyAlorithm: opts.Algorithm,
		keyUsage:    opts.KeyUsage,
	}
	reader := rand.Reader
	if keystores.KeyAlgRSA2048.Oid.Equal(opts.Algorithm.Oid) {
		var err error
		imkp.privKey, err = rsa.GenerateKey(reader, opts.Algorithm.KeyLength)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
	} else if keystores.KeyAlgECP256.Equal(opts.Algorithm) {
		var err error
		imkp.privKey, err = ecdsa.GenerateKey(elliptic.P256(), reader)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
	} else if keystores.KeyAlgEd25519.Equal(opts.Algorithm) {
		var err error
		_, imkp.privKey, err = ed25519.GenerateKey(reader)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm: %s", opts.Algorithm))
	}

	if imks.keyPairs == nil {
		imks.keyPairs = make([]*InMemoryKeyPair, 1)
		imks.keyPairs[0] = &imkp
	} else {
		imks.keyPairs = append(imks.keyPairs, &imkp)
	}
	return &imkp, nil
}

func (imks *InMemoryKeyStore) ImportKeyPair(der []byte) (keystores.KeyPair, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	imkp := InMemoryKeyPair{
		keySore: imks,
	}
	if rsaKey, ok := key.(rsa.PrivateKey); ok {
		imkp.privKey = rsaKey
	} else if ecKey, ok := key.(ecdsa.PrivateKey); ok {
		imkp.privKey = ecKey
	} else if edKey, ok := key.(ed25519.PrivateKey); ok {
		imkp.privKey = edKey
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm"))
	}

	if imks.keyPairs == nil {
		imks.keyPairs = make([]*InMemoryKeyPair, 1)
		imks.keyPairs[0] = &imkp
	} else {
		imks.keyPairs = append(imks.keyPairs, &imkp)
	}
	return &imkp, nil
}

func CreateInMemoryKeyStore() *InMemoryKeyStore {
	return new(InMemoryKeyStore)
}
