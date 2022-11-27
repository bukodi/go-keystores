package pkcs11ks

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	"github.com/pkg/errors"
)

func (ks *Pkcs11KeyStore) newECCKeyPair(privKeyObject *ECCPrivateKeyAttributes, pubKeyObject *ECCPublicKeyAttributes) (*Pkcs11KeyPair, error) {
	kp := Pkcs11KeyPair{
		keyStore:        ks,
		eccPrivKeyAttrs: privKeyObject,
		eccPubKeyAttrs:  pubKeyObject,
	}

	if pubKeyObject.CKA_KEY_TYPE == CKK_EC {
		pubKeyBytes := bytesFrom_CK_Bytes(pubKeyObject.CKA_EC_POINT)
		if ecPub, err := x509.ParsePKIXPublicKey(pubKeyBytes); err != nil {
			return nil, keystores.ErrorHandler(err)
		} else if ecdsaPub, ok := ecPub.(ecdsa.PublicKey); !ok {
			return nil, keystores.ErrorHandler(errors.Errorf("public key isn't an ecdsa.PublicKey: %+v", ecPub))
		} else {
			kp.eccPublicKey = ecdsaPub
		}
	} else {
		return nil, keystores.ErrorHandler(errors.Errorf("unsupported elliptic curve type: CKA_KEY_TYPE=%d", pubKeyObject.CKA_KEY_TYPE))
	}

	id, err := keystores.GenerateKeyPairIdFromPubKey(kp.eccPublicKey)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.id = id

	return &kp, nil
}
