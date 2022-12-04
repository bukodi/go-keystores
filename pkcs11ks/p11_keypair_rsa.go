package pkcs11ks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"math/big"
)

// newRSAKeyPair creates a new Pkcs11KeyPair instance from the existing PKCS11 objects
func (ks *Pkcs11KeyStore) newRSAKeyPair(privKeyObject *RSAPrivateKeyAttributes, pubKeyObject *RSAPublicKeyAttributes) (*Pkcs11KeyPair, error) {
	kp := Pkcs11KeyPair{
		keyStore:        ks,
		rsaPrivKeyAttrs: privKeyObject,
		rsaPubKeyAttrs:  pubKeyObject,
	}

	kp.rsaPublicKey = &rsa.PublicKey{}
	kp.rsaPublicKey.N = kp.rsaPrivKeyAttrs.CKA_MODULUS
	kp.rsaPublicKey.E = int((*big.Int)(kp.rsaPrivKeyAttrs.CKA_PUBLIC_EXPONENT).Int64())

	id, err := keystores.GenerateKeyPairIdFromPubKey(kp.rsaPublicKey)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.id = id

	return &kp, nil
}

// createRSAKeyPair creates a new RSA key pair on the underlying PKCS11 keystore
func (ks *Pkcs11KeyStore) createRSAKeyPair(opts keystores.GenKeyPairOpts, privateKeyTemplate []*p11api.Attribute, publicKeyTemplate []*p11api.Attribute) (*Pkcs11KeyPair, error) {
	publicKeyTemplate = append(publicKeyTemplate,
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, opts.Algorithm.RSAKeyLength),
	)

	mechs := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}

	hPub, hPriv, err := ks.provider.pkcs11Ctx.GenerateKeyPair(ks.hSession,
		mechs,
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var privKeyAttrs RSAPrivateKeyAttributes
	var pubKeyAttrs RSAPublicKeyAttributes
	if err := getP11Attributes(ks, hPriv, &privKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if err := getP11Attributes(ks, hPub, &pubKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp, err := ks.newRSAKeyPair(&privKeyAttrs, &pubKeyAttrs)
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
	kp.rsaPrivKeyAttrs.CKA_ID = ckaId
	if err = ks.provider.pkcs11Ctx.SetAttributeValue(ks.hSession, hPub,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.rsaPubKeyAttrs.CKA_ID = ckaId

	return kp, nil
}
