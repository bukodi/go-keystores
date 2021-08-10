package inmemoryks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/pkg/errors"
	"io"
	"math/big"
	"unsafe"
)

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

type InMemoryKeyPair struct {
	privKey     crypto.PrivateKey
	keySore     *InMemoryKeyStore
	id          keystores.KeyPairId
	keyAlorithm keystores.KeyAlgorithm
	label       string
	keyUsage    x509.KeyUsage
}

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &InMemoryKeyPair{}

func (i *InMemoryKeyPair) Id() keystores.KeyPairId {
	return i.id
}

func (i *InMemoryKeyPair) Label() string {
	return i.label
}

func (i *InMemoryKeyPair) KeyUsage() x509.KeyUsage {
	return i.keyUsage
}

func (i *InMemoryKeyPair) Algorithm() keystores.KeyAlgorithm {
	return i.keyAlorithm
}

func (i *InMemoryKeyPair) KeyStore() keystores.KeyStore {
	return i.keySore
}

func (i *InMemoryKeyPair) Public() crypto.PublicKey {
	if rsaKey, ok := i.privKey.(*rsa.PrivateKey); ok {
		return rsaKey.Public()
	} else if ecKey, ok := i.privKey.(*ecdsa.PrivateKey); ok {
		return ecKey.Public()
	} else if edKey, ok := i.privKey.(ed25519.PrivateKey); ok {
		return edKey.Public()
	} else {
		panic(keystores.ErrorHandler(fmt.Errorf("unsupported algorithm")))
	}
}

func (i *InMemoryKeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if rsaKey, ok := i.privKey.(*rsa.PrivateKey); ok {
		signature, err = rsaKey.Sign(rand, digest, opts)
	} else if ecKey, ok := i.privKey.(*ecdsa.PrivateKey); ok {
		signature, err = ecKey.Sign(rand, digest, opts)
	} else if edKey, ok := i.privKey.(ed25519.PrivateKey); ok {
		signature, err = edKey.Sign(rand, digest, crypto.Hash(0))
	} else {
		signature, err = nil, keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm"))
	}
	if err != nil {
		err = keystores.ErrorHandler(err)
	}
	return signature, err
}

func (i *InMemoryKeyPair) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if rsaKey, ok := i.privKey.(rsa.PrivateKey); ok {
		return rsaKey.Decrypt(rand, msg, opts)
	} else if _, ok := i.privKey.(ecdsa.PrivateKey); ok {
		// TODO: https://asecuritysite.com/encryption/goecdh
		panic(keystores.ErrorHandler(fmt.Errorf("not implemented operation")))
	} else if _, ok := i.privKey.(ed25519.PrivateKey); ok {
		panic(keystores.ErrorHandler(fmt.Errorf("unsupported operation")))
	} else {
		panic(keystores.ErrorHandler(fmt.Errorf("unsupported algorithm")))
	}
}

func (i *InMemoryKeyPair) ExportPrivate() (privKey crypto.PrivateKey, err error) {
	return i.privKey, nil
}

func (i *InMemoryKeyPair) Destroy() error {
	for idx, kp := range i.keySore.keyPairs {
		if i.id == kp.id {
			i.keySore.keyPairs = append(i.keySore.keyPairs[:idx], i.keySore.keyPairs[idx+1:]...)
			return nil
		}
	}
	return keystores.ErrorHandler(errors.Errorf("key not found"))
}

func (i *InMemoryKeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	pubKey := i.Public()
	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		err = rsa.VerifyPKCS1v15(rsaKey, opts.HashFunc(), digest, signature)
		return keystores.ErrorHandler(err)
	} else if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
		type ECDSASignature struct {
			R, S *big.Int
		}
		// unmarshal the R and S components of the ASN.1-encoded signature into our
		// signature data structure
		sig := &ECDSASignature{}
		_, err = asn1.Unmarshal(signature, sig)
		if err != nil {
			return keystores.ErrorHandler(err)
		}
		// validate the signature!
		valid := ecdsa.Verify(
			ecKey,
			digest,
			sig.R,
			sig.S,
		)
		if !valid {
			return keystores.ErrorHandler(fmt.Errorf("Signature validation failed"))
		}
		return nil
	} else if edKey, ok := pubKey.(ed25519.PublicKey); ok {
		valid := ed25519.Verify(edKey, digest, signature)
		if !valid {
			return keystores.ErrorHandler(fmt.Errorf("Signature validation failed"))
		}
		return nil
	} else {
		panic(keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm")))
	}
}
