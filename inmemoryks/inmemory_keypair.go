package inmemoryks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/bukodi/go-keystores"
	"io"
	"math/big"
)

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

func (i *InMemoryKeyPair) ExportPrivate() (key crypto.PrivateKey, err error) {
	return i.privKey, nil
}

func (i *InMemoryKeyPair) ExportPublic() (der []byte, err error) {
	return x509.MarshalPKIXPublicKey(i.Public())
}

func (i *InMemoryKeyPair) Destroy() error {
	panic("implement me")
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
