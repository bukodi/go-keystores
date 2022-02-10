package inmemoryks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	"sort"
	"unsafe"
)

type InMemoryKeyStore struct {
	keyPairs map[keystores.KeyPairId]*InMemoryKeyPair
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
	ret := make([]keystores.KeyPair, 0, len(imks.keyPairs))
	for _, kp := range imks.keyPairs {
		ret = append(ret, kp)
	}
	// Order lexicographically for stable response
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].Id() < ret[j].Id()
	})
	return ret, nil
}

func (imks *InMemoryKeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	imkp, err := generateKeyPair(opts)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	imkp.keyStore = imks
	imks.keyPairs[imkp.id] = imkp
	return imkp, nil
}

func (imks *InMemoryKeyStore) ImportKeyPair(der []byte) (keystores.KeyPair, error) {
	imkp, err := parsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	imkp.keyStore = imks
	imks.keyPairs[imkp.id] = imkp
	return imkp, nil
}

func CreateInMemoryKeyStore() *InMemoryKeyStore {
	imKs := InMemoryKeyStore{
		keyPairs: make(map[keystores.KeyPairId]*InMemoryKeyPair, 0),
	}
	return &imKs
}
