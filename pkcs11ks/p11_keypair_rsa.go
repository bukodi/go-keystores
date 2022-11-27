package pkcs11ks

import (
	"crypto/rsa"
	"github.com/bukodi/go-keystores"
	"math/big"
)

func (ks *Pkcs11KeyStore) newRSAKeyPair(privKeyObject *RSAPrivateKeyAttributes, pubKeyObject *RSAPublicKeyAttributes) (*Pkcs11KeyPair, error) {
	kp := Pkcs11KeyPair{
		keyStore:        ks,
		rsaPrivKeyAttrs: privKeyObject,
		rsaPubKeyAttrs:  pubKeyObject,
	}

	kp.rsaPublicKey = &rsa.PublicKey{}
	kp.rsaPublicKey.N = big.NewInt(0)
	kp.rsaPublicKey.N.SetBytes(kp.rsaPrivKeyAttrs.CKA_MODULUS)
	kp.rsaPublicKey.N.SetBytes(kp.rsaPrivKeyAttrs.CKA_MODULUS)
	bigExponent := big.NewInt(0)
	bigExponent.SetBytes(kp.rsaPrivKeyAttrs.CKA_PUBLIC_EXPONENT)
	kp.rsaPublicKey.E = int(bigExponent.Uint64())

	id, err := keystores.GenerateKeyPairIdFromPubKey(kp.rsaPublicKey)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.id = id

	return &kp, nil
}
