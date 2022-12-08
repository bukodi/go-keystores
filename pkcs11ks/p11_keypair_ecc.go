package pkcs11ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/pkg/errors"
	"io"
	"math/big"
)

func (ks *Pkcs11KeyStore) newECCKeyPair(privKeyObject *ECCPrivateKeyAttributes, pubKeyObject *ECCPublicKeyAttributes) (*Pkcs11KeyPair, error) {
	kp := Pkcs11KeyPair{
		keyStore:        ks,
		eccPrivKeyAttrs: privKeyObject,
		eccPubKeyAttrs:  pubKeyObject,
	}

	if pubKeyObject.CKA_KEY_TYPE == CKK_EC {
		ecParamsBytes := bytesFrom_CK_Bytes(pubKeyObject.CKA_EC_PARAMS)
		keyAlg, err := parseEcParams(ecParamsBytes)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		x, y, err := parseEcPoint(pubKeyObject.CKA_EC_POINT, keyAlg.ECCCurve)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		ecPubKey := ecdsa.PublicKey{
			Curve: keyAlg.ECCCurve,
			X:     x,
			Y:     y,
		}
		kp.eccPublicKey = &ecPubKey
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

func parseEcParams(bytes []byte) (*keystores.KeyAlgorithm, error) {
	var ecCurveOid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(bytes, &ecCurveOid)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	keyAlg := keystores.ECCAlgorithmByOid[ecCurveOid.String()]
	if keyAlg == nil {
		return nil, keystores.ErrorHandler(fmt.Errorf("%w : %s", keystores.ErrAlgorithmNotSupportedByKeyStore, ecCurveOid.String()))
	}
	return keyAlg, nil
}

func parseEcPoint(bytes []byte, c elliptic.Curve) (*big.Int, *big.Int, error) {
	var pointBytes []byte
	_, err := asn1.Unmarshal(bytes, &pointBytes)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}

	x, y := elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		return nil, nil, keystores.ErrorHandler(errors.New("failed to parse elliptic curve point"))
	}
	return x, y, nil
}

func (kp *Pkcs11KeyPair) ecdsaSign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, keystores.ErrOperationNotSupportedByKeyStore
}
