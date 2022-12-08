package inmemoryks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	"unsafe"
)

type InMemoryKeyStore struct {
	isLoaded  bool
	persister Persister
	keyPairs  map[keystores.KeyPairId]*InMemoryKeyPair
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
	err := imks.persister.Load(imks)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	imks.isLoaded = true
	return nil
}

func (imks *InMemoryKeyStore) Close() error {
	imks.isLoaded = false
	return nil
}

func (imks *InMemoryKeyStore) IsOpen() bool {
	return imks.isLoaded
}

func (imks *InMemoryKeyStore) Reload() error {
	return nil
}

func (imks *InMemoryKeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{
		keystores.KeyAlgRSA1024,
		keystores.KeyAlgRSA2048,
		keystores.KeyAlgRSA3072,
		keystores.KeyAlgRSA4096,
		keystores.KeyAlgECP224,
		keystores.KeyAlgECP256,
		keystores.KeyAlgECP384,
		keystores.KeyAlgECP521,
	}
	return algs
}

func (imks *InMemoryKeyStore) KeyPairById(id keystores.KeyPairId) keystores.KeyPair {
	if kps, err := imks.KeyPairs(false); err == nil {
		kp := kps[id]
		if kp != nil {
			return kp
		}
	}
	return nil
}

func (imks *InMemoryKeyStore) KeyPairs(reload bool) (keyPairs map[keystores.KeyPairId]keystores.KeyPair, errs error) {
	if (reload || imks.keyPairs == nil) && imks.persister != nil {
		imks.persister.Load(imks)
	} else if imks.keyPairs == nil {
		imks.keyPairs = make(map[keystores.KeyPairId]*InMemoryKeyPair)
	}

	keyPairs = make(map[keystores.KeyPairId]keystores.KeyPair)
	for k, v := range imks.keyPairs {
		keyPairs[k] = v
	}
	return keyPairs, nil
}

func (imks *InMemoryKeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	imkp, err := generateKeyPair(opts)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	imkp.keyStore = imks
	if err := imks.persister.SaveKeyPair(imkp); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	imks.keyPairs[imkp.id] = imkp
	return imkp, nil
}

func (imks *InMemoryKeyStore) ImportKeyPair(der []byte) (keystores.KeyPair, error) {
	imkp, err := parsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	imkp.keyStore = imks
	if err := imks.persister.SaveKeyPair(imkp); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	imks.keyPairs[imkp.id] = imkp
	return imkp, nil
}

func CreateInMemoryKeyStore() *InMemoryKeyStore {
	imKs := InMemoryKeyStore{
		keyPairs:  make(map[keystores.KeyPairId]*InMemoryKeyPair, 0),
		persister: &NopPersister{},
	}
	return &imKs
}
