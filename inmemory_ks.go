package keystores

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"github.com/pkg/errors"
	"io"
	"math/big"
)

type InMemoryKeyStore struct {
	keyPairs []*InMemoryKeyPair
}

func (imks *InMemoryKeyStore) SupportedPrivateKeyAlgorithms() []KeyAlgorithm {
	algs := []KeyAlgorithm{KeyAlgRSA2048, KeyAlgECP256}
	return algs
}

func (imks *InMemoryKeyStore) KeyPairs() []KeyPair {
	if imks.keyPairs == nil {
		return make([]KeyPair, 0)
	}
	ret := make([]KeyPair, len(imks.keyPairs))
	for i, kp := range imks.keyPairs {
		ret[i] = kp
	}
	return ret
}

func (imks *InMemoryKeyStore) CreateKeyPair(keyAlgorithm KeyAlgorithm, opts interface{}) (KeyPair, error) {

	imkp := InMemoryKeyPair{
		keySore:     imks,
		keyAlorithm: keyAlgorithm,
	}
	reader := rand.Reader
	if KeyAlgRSA2048.oid.Equal(keyAlgorithm.oid) {
		var err error
		imkp.privKey, err = rsa.GenerateKey(reader, keyAlgorithm.keyLength)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else if KeyAlgECP256.Equal(keyAlgorithm) {
		var err error
		imkp.privKey, err = ecdsa.GenerateKey(elliptic.P256(), reader)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else if KeyAlgEd25519.Equal(keyAlgorithm) {
		var err error
		_, imkp.privKey, err = ed25519.GenerateKey(reader)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		return nil, errors.WithStack(errors.Errorf("Unsupported algorithm: %s", keyAlgorithm.name))
	}

	if imks.keyPairs == nil {
		imks.keyPairs = make([]*InMemoryKeyPair, 1)
		imks.keyPairs[0] = &imkp
	} else {
		imks.keyPairs = append(imks.keyPairs, &imkp)
	}
	return &imkp, nil
}

func (imks *InMemoryKeyStore) ImportKeyPair(der []byte) (KeyPair, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.WithStack(err)
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
		return nil, errors.WithStack(errors.Errorf("Unsupported algorithm"))
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
	id          KeyPairId
	keyAlorithm KeyAlgorithm
	label       string
}

func (i InMemoryKeyPair) Id() KeyPairId {
	return i.id
}

func (i InMemoryKeyPair) Algorithm() KeyAlgorithm {
	return i.keyAlorithm
}

func (i InMemoryKeyPair) KeyStore() KeyStore {
	return i.keySore
}

func (i InMemoryKeyPair) Public() crypto.PublicKey {
	if rsaKey, ok := i.privKey.(*rsa.PrivateKey); ok {
		return rsaKey.Public()
	} else if ecKey, ok := i.privKey.(*ecdsa.PrivateKey); ok {
		return ecKey.Public()
	} else if edKey, ok := i.privKey.(ed25519.PrivateKey); ok {
		return edKey.Public()
	} else {
		panic(errors.WithStack(errors.Errorf("Unsupported algorithm")))
	}
}

func (i InMemoryKeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if rsaKey, ok := i.privKey.(*rsa.PrivateKey); ok {
		signature, err = rsaKey.Sign(rand, digest, opts)
	} else if ecKey, ok := i.privKey.(*ecdsa.PrivateKey); ok {
		signature, err = ecKey.Sign(rand, digest, opts)
	} else if edKey, ok := i.privKey.(ed25519.PrivateKey); ok {
		signature, err = edKey.Sign(rand, digest, crypto.Hash(0))
	} else {
		signature, err = nil, errors.WithStack(errors.Errorf("Unsupported key algorithm"))
	}
	if err != nil {
		err = errors.WithStack(err)
	}
	return signature, err
}

func (i InMemoryKeyPair) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if rsaKey, ok := i.privKey.(rsa.PrivateKey); ok {
		return rsaKey.Decrypt(rand, msg, opts)
	} else if _, ok := i.privKey.(ecdsa.PrivateKey); ok {
		// TODO: https://asecuritysite.com/encryption/goecdh
		panic(errors.WithStack(errors.Errorf("Not implemented operation")))
	} else if _, ok := i.privKey.(ed25519.PrivateKey); ok {
		panic(errors.WithStack(errors.Errorf("Unsupported operation")))
	} else {
		panic(errors.WithStack(errors.Errorf("Unsupported algorithm")))
	}
}

func (i InMemoryKeyPair) ExportPrivate() (der []byte, err error) {
	return x509.MarshalPKCS8PrivateKey(i.privKey)
}

func (i InMemoryKeyPair) ExportPublic() (der []byte, err error) {
	return x509.MarshalPKIXPublicKey(i.Public())
}

func (i InMemoryKeyPair) Destroy() {
	panic("implement me")
}

func (i InMemoryKeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	pubKey := i.Public()
	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		err = rsa.VerifyPKCS1v15(rsaKey, opts.HashFunc(), digest, signature)
		return errors.WithStack(err)
	} else if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
		type ECDSASignature struct {
			R, S *big.Int
		}
		// unmarshal the R and S components of the ASN.1-encoded signature into our
		// signature data structure
		sig := &ECDSASignature{}
		_, err = asn1.Unmarshal(signature, sig)
		if err != nil {
			return err
		}
		// validate the signature!
		valid := ecdsa.Verify(
			ecKey,
			digest,
			sig.R,
			sig.S,
		)
		if !valid {
			return errors.WithStack(errors.New("Signature validation failed"))
		}
		return nil
	} else if edKey, ok := pubKey.(ed25519.PublicKey); ok {
		valid := ed25519.Verify(edKey, digest, signature)
		if !valid {
			return errors.WithStack(errors.New("Signature validation failed"))
		}
		return nil
	} else {
		panic(errors.WithStack(errors.Errorf("Unsupported key algorithm")))
	}
}
