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
func (ks *Pkcs11KeyStore) createECCKeyPair(sess *Pkcs11Session, opts keystores.GenKeyPairOpts, privateKeyTemplate []*p11api.Attribute, publicKeyTemplate []*p11api.Attribute) (*Pkcs11KeyPair, error) {
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

	hPub, hPriv, err := sess.ctx.GenerateKeyPair(sess.hSession,
		mechs,
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var privKeyAttrs ECCPrivateKeyAttributes
	var pubKeyAttrs ECCPublicKeyAttributes
	if err := getP11Attributes(sess, hPriv, &privKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if err := getP11Attributes(sess, hPub, &pubKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
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
	if err = sess.ctx.SetAttributeValue(sess.hSession, hPriv,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.eccPrivKeyAttrs.CKA_ID = ckaId
	if err = sess.ctx.SetAttributeValue(sess.hSession, hPub,
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

func (kp *Pkcs11KeyPair) ecdsaSign(sess *Pkcs11Session, _ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hPrivKey, err := kp.privateKeyHandle(sess)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	mech := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_ECDSA, nil)}
	if err = sess.ctx.SignInit(sess.hSession, mech, hPrivKey); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var sigBytes []byte
	if sigBytes, err = sess.ctx.Sign(sess.hSession, digest); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	type ECDSASignature struct {
		R, S *big.Int
	}
	asn1Sig := ECDSASignature{
		R: big.NewInt(0),
		S: big.NewInt(0),
	}
	asn1Sig.R.SetBytes(sigBytes[0 : len(sigBytes)/2])
	asn1Sig.S.SetBytes(sigBytes[len(sigBytes)/2:])

	if asn1Bytes, err := asn1.Marshal(asn1Sig); err != nil {
		return nil, keystores.ErrorHandler(err)
	} else {
		return asn1Bytes, nil
	}
}

func (kp *Pkcs11KeyPair) ecdhAgree(sess *Pkcs11Session, remote *ecdsa.PublicKey) ([]byte, error) {
	hPrivKey, err := kp.privateKeyHandle(sess)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	// Check this and remote uses the same curve
	curve := kp.eccPublicKey.Curve

	template := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_TOKEN, false),
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_SECRET_KEY),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_GENERIC_SECRET),
		p11api.NewAttribute(p11api.CKA_SENSITIVE, false),
		p11api.NewAttribute(p11api.CKA_EXTRACTABLE, true),
		p11api.NewAttribute(p11api.CKA_ENCRYPT, true),
		p11api.NewAttribute(p11api.CKA_DECRYPT, true),
		p11api.NewAttribute(p11api.CKA_WRAP, true),
		p11api.NewAttribute(p11api.CKA_UNWRAP, true),
		p11api.NewAttribute(p11api.CKA_VALUE_LEN, (curve.Params().BitSize+7)/8),
	}
	params := p11api.ECDH1DeriveParams{KDF: p11api.CKD_NULL, PublicKeyData: elliptic.Marshal(curve, remote.X, remote.Y)}
	mech := []*p11api.Mechanism{
		p11api.NewMechanism(p11api.CKM_ECDH1_DERIVE, &params),
	}

	fmt.Printf("template before DeriveKey (ckULONGis32bit is %t): \n%s", kp.keyStore.provider.ckULONGis32bit, dumpAttrs(template))

	var hSharedKey p11api.ObjectHandle
	if hSharedKey, err = sess.ctx.DeriveKey(sess.hSession, mech, hPrivKey, template); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	template2 := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_VALUE, nil),
	}
	attr, err := sess.ctx.GetAttributeValue(sess.hSession, hSharedKey, template2)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	return attr[0].Value, nil
}
