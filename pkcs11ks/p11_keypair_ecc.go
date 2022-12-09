package pkcs11ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
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
		kp.keyAlgorithm = keystores.KeyAlgorithm{
			Oid:          keyAlg.Oid,
			RSAKeyLength: 0,
			ECCCurve:     keyAlg.ECCCurve,
			Name:         keyAlg.Name,
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

// createECCKeyPair creates a new Elliptic key pair on the underlying PKCS11 keystore
func (ks *Pkcs11KeyStore) createECCKeyPair(opts keystores.GenKeyPairOpts, privateKeyTemplate []*p11api.Attribute, publicKeyTemplate []*p11api.Attribute) (*Pkcs11KeyPair, error) {
	oidUint8, err := asn1.Marshal(opts.Algorithm.Oid)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	oidBytes := make([]byte, len(oidUint8))
	for i, ui8 := range oidUint8 {
		oidBytes[i] = ui8
	}
	publicKeyTemplate = append(publicKeyTemplate,
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_EC),
		p11api.NewAttribute(p11api.CKA_EC_PARAMS, oidBytes),
	)

	mechs := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_EC_KEY_PAIR_GEN, nil)}

	hPub, hPriv, err := ks.provider.pkcs11Ctx.GenerateKeyPair(ks.hSession,
		mechs,
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var privKeyAttrs ECCPrivateKeyAttributes
	var pubKeyAttrs ECCPublicKeyAttributes
	if err := getP11Attributes(ks, hPriv, &privKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if err := getP11Attributes(ks, hPub, &pubKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp, err := ks.newECCKeyPair(&privKeyAttrs, &pubKeyAttrs)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	// Generate ID
	var ckaId []byte
	if ckaId, err = hex.DecodeString(string(kp.Id())); err == nil && len(ckaId) >= 8 {
		ckaId = ckaId[0:8]
	} else {
		ckaId = make([]byte, 8)
		rand.Read(ckaId)
	}
	// Set attribute CKA_ID both on private and public key
	if err = ks.provider.pkcs11Ctx.SetAttributeValue(ks.hSession, hPriv,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.eccPrivKeyAttrs.CKA_ID = ckaId
	if err = ks.provider.pkcs11Ctx.SetAttributeValue(ks.hSession, hPub,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.eccPubKeyAttrs.CKA_ID = ckaId

	return kp, nil
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
