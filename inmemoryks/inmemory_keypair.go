package inmemoryks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/bukodi/go-keystores"
	"io"
	"math/big"
)

type InMemoryKeyPair struct {
	// TODO: Use https://github.com/awnumar/memguard
	privKey     crypto.PrivateKey
	pubKey      crypto.PublicKey
	keyStore    *InMemoryKeyStore
	id          keystores.KeyPairId
	keyAlorithm keystores.KeyAlgorithm
	label       string
	keyUsage    map[keystores.KeyUsage]bool
}

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &InMemoryKeyPair{}

func parsePKCS8PrivateKey(der []byte) (*InMemoryKeyPair, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var imkp InMemoryKeyPair
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		imkp.privKey = rsaKey
		imkp.pubKey = rsaKey.Public()
	} else if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		imkp.privKey = ecKey
		imkp.pubKey = ecKey.Public()
	} else if edKey, ok := key.(ed25519.PrivateKey); ok {
		imkp.privKey = edKey
		imkp.pubKey = edKey.Public()
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm"))
	}

	if imkp.id, err = keystores.IdFromPublicKey(imkp.pubKey); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if imkp.keyAlorithm, err = keystores.AlgorithmFromPublicKey(imkp.pubKey); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	return &imkp, nil
}

func generateKeyPair(opts keystores.GenKeyPairOpts) (*InMemoryKeyPair, error) {
	imkp := InMemoryKeyPair{
		keyAlorithm: opts.Algorithm,
		keyUsage:    opts.KeyUsage,
		label:       opts.Label,
	}
	reader := rand.Reader
	if opts.Algorithm.RSAKeyLength > 0 {
		rsaKey, err := rsa.GenerateKey(reader, opts.Algorithm.RSAKeyLength)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		imkp.privKey = rsaKey
		imkp.pubKey = rsaKey.Public()
	} else if opts.Algorithm.ECCCurve != nil {
		ecKey, err := ecdsa.GenerateKey(opts.Algorithm.ECCCurve, reader)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		imkp.privKey = ecKey
		imkp.pubKey = ecKey.Public()
	} else if keystores.KeyAlgEd25519.Equal(opts.Algorithm) {
		edPub, edPriv, err := ed25519.GenerateKey(reader)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		imkp.privKey = edPriv
		imkp.pubKey = edPub
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm: %s", opts.Algorithm))
	}
	var err error
	if imkp.id, err = keystores.IdFromPublicKey(imkp.Public()); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	return &imkp, nil
}

func (i *InMemoryKeyPair) Id() keystores.KeyPairId {
	return i.id
}

func (i *InMemoryKeyPair) Label() string {
	return i.label
}

func (i *InMemoryKeyPair) SetLabel(label string) error {
	i.label = label
	if i.keyStore.persister != nil {
		err := i.keyStore.persister.SaveKeyPair(i)
		if err != nil {
			return keystores.ErrorHandler(err)
		}
	}
	return nil
}

func (i *InMemoryKeyPair) KeyUsage() map[keystores.KeyUsage]bool {
	return i.keyUsage
}

func (i *InMemoryKeyPair) Algorithm() keystores.KeyAlgorithm {
	return i.keyAlorithm
}

func (i *InMemoryKeyPair) KeyStore() keystores.KeyStore {
	return i.keyStore
}

func (i *InMemoryKeyPair) Public() crypto.PublicKey {
	return i.pubKey
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
	if rsaKey, ok := i.privKey.(*rsa.PrivateKey); ok {
		return rsaKey.Decrypt(rand, msg, opts)
	} else if edsaKey, ok := i.privKey.(ecdsa.PrivateKey); ok {
		if ecdsaKey, err := edsaKey.ECDH(); err != nil {
			return nil, keystores.ErrorHandler(err)
		} else {
			return ecdsaKey.ECDH()Decrypt(rand, msg, opts)
		}
		// TODO: https://asecuritysite.com/encryption/goecdh
		plaintext, err = nil, keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm"))
	} else if _, ok := i.privKey.(ed25519.PrivateKey); ok {
		// TODO: rfc7748
		plaintext, err = nil, keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm"))
	} else {
		plaintext, err = nil, keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm"))
	}
	return
}

func (i *InMemoryKeyPair) ExportPrivate() (key crypto.PrivateKey, err error) {
	return i.privKey, nil
}

func (i *InMemoryKeyPair) ExportPublic() (der []byte, err error) {
	return x509.MarshalPKIXPublicKey(i.Public())
}

func (i *InMemoryKeyPair) Destroy() error {
	i.privKey = nil
	delete(i.keyStore.keyPairs, i.id)
	return nil
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
		return keystores.ErrorHandler(fmt.Errorf("unsupported key algorithm"))
	}
}

func (i *InMemoryKeyPair) Attestation(nonce []byte) (att keystores.Attestation, err error) {
	return nil, nil
}
