package pkcs11ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
	p11api "github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"io"
)

type Pkcs11KeyPair struct {
	keyStore     *Pkcs11KeyStore
	id           keystores.KeyPairId
	keyAlgorithm keystores.KeyAlgorithm

	// RSA part
	rsaPublicKey    *rsa.PublicKey
	rsaPrivKeyAttrs *RSAPrivateKeyAttributes
	rsaPubKeyAttrs  *RSAPublicKeyAttributes

	// ECC part
	eccPublicKey    *ecdsa.PublicKey
	eccPrivKeyAttrs *ECCPrivateKeyAttributes
	eccPubKeyAttrs  *ECCPublicKeyAttributes
}

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &Pkcs11KeyPair{}

func (kp *Pkcs11KeyPair) privateKeyHandle(sess *Pkcs11Session) (hPriv p11api.ObjectHandle, retErr error) {
	// Query priv key object by CKA_CLASS and CKA_ID
	classBytes := bytesFrom_CK_OBJECT_CLASS(kp.commonPrivateKeyAttributes().CKA_CLASS, kp.keyStore.provider.ckULONGis32bit)
	if err := sess.ctx.FindObjectsInit(sess.hSession, []*p11api.Attribute{
		{p11api.CKA_CLASS, classBytes},
		{p11api.CKA_ID, bytesFrom_CK_Bytes(kp.commonPrivateKeyAttributes().CKA_ID)},
	}); err != nil {
		return 0, keystores.ErrorHandler(err, kp)
	}
	defer func() {
		err := sess.ctx.FindObjectsFinal(sess.hSession)
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
	}()

	hObjs, _, err := sess.ctx.FindObjects(sess.hSession, 100)
	if err != nil {
		return 0, keystores.ErrorHandler(err)
	} else if len(hObjs) == 0 {
		return 0, keystores.ErrorHandler(
			fmt.Errorf("private key not found with CKA_CLASS=%v and CKA_ID=%v",
				kp.commonPrivateKeyAttributes().CKA_CLASS,
				kp.commonPrivateKeyAttributes().CKA_ID))
	} else if len(hObjs) > 1 {
		return 0, keystores.ErrorHandler(
			fmt.Errorf("more than one (%d) private key found with CKA_CLASS=%v and CKA_ID=%v", len(hObjs),
				kp.commonPrivateKeyAttributes().CKA_CLASS,
				kp.commonPrivateKeyAttributes().CKA_ID))
	} else {
		return hObjs[0], nil
	}
}

func (kp *Pkcs11KeyPair) Public() crypto.PublicKey {
	if kp.rsaPublicKey != nil {
		return kp.rsaPublicKey
	} else if kp.eccPublicKey != nil {
		return kp.eccPublicKey
	} else {
		panic("not implemented")
	}

}

func (kp *Pkcs11KeyPair) Label() string {
	l := string(kp.commonPrivateKeyAttributes().CKA_LABEL)
	if len(l) == 0 {
		pubKeyAttrs := kp.commonPublicKeyAttributes()
		if pubKeyAttrs != nil {
			l = string(kp.rsaPubKeyAttrs.CKA_LABEL)
		}
		if len(l) == 0 {
			return "<no lable>"
		}
	}
	return l
}

func (kp *Pkcs11KeyPair) SetLabel(label string) error {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Attestation(nonce []byte) (att keystores.Attestation, err error) {
	//TODO implement me
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Id() keystores.KeyPairId {
	return kp.id
}

func (kp *Pkcs11KeyPair) KeyUsage() map[keystores.KeyUsage]bool {
	ku := make(map[keystores.KeyUsage]bool, 0)
	if kp.commonPrivateKeyAttributes().CKA_SIGN {
		ku[keystores.KeyUsageSign] = true
	}
	if kp.commonPrivateKeyAttributes().CKA_DECRYPT {
		ku[keystores.KeyUsageDecrypt] = true
	}
	if kp.commonPrivateKeyAttributes().CKA_UNWRAP {
		ku[keystores.KeyUsageUnwrap] = true
	}
	if kp.commonPrivateKeyAttributes().CKA_DERIVE {
		ku[keystores.KeyUsageDerive] = true
	}
	return ku
}

func (kp *Pkcs11KeyPair) Algorithm() keystores.KeyAlgorithm {
	return kp.keyAlgorithm
}

func (kp *Pkcs11KeyPair) KeyStore() keystores.KeyStore {
	return kp.keyStore
}

func (kp *Pkcs11KeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sess, err := kp.keyStore.aquireSession()
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)

	if kp.rsaPublicKey != nil {
		return kp.rsaSign(sess, rand, digest, opts)
	} else if kp.eccPublicKey != nil {
		return kp.ecdsaSign(sess, rand, digest, opts)
	} else {
		return nil, keystores.ErrorHandler(keystores.ErrAlgorithmNotSupportedByKeyStore)
	}
}

func (kp *Pkcs11KeyPair) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	sess, err := kp.keyStore.aquireSession()
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)
	if kp.rsaPublicKey != nil {
		if plaintext, err := kp.rsaDecrypt(sess, rand, ciphertext, opts); err != nil {
			return nil, keystores.ErrorHandler(err)
		} else {
			return plaintext, nil
		}
	} else if kp.eccPublicKey != nil {
		return nil, keystores.ErrorHandler(keystores.ErrAlgorithmNotSupportedByKeyStore)
	} else {
		return nil, keystores.ErrorHandler(keystores.ErrAlgorithmNotSupportedByKeyStore)
	}
}

func (kp *Pkcs11KeyPair) ExportPrivate() (privKey crypto.PrivateKey, err error) {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Destroy() (retErr error) {
	sess, err := kp.keyStore.aquireSession()
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)

	if cntDelete, err := kp.keyStore.destroyObject(sess, kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID, ""); err != nil {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
	} else if cntDelete > 1 {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("more than one object with (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID)))
	} else if cntDelete == 0 {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("private key not deleted (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID)))
	}

	if kp.commonPublicKeyAttributes() != nil {
		if cntDelete, err := kp.keyStore.destroyObject(sess, kp.commonPublicKeyAttributes().CKA_CLASS, kp.commonPublicKeyAttributes().CKA_ID, ""); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
		} else if cntDelete > 1 {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("more than one object with (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPublicKeyAttributes().CKA_CLASS, kp.commonPublicKeyAttributes().CKA_ID)))
		} else if cntDelete == 0 {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("public key not deleted (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPublicKeyAttributes().CKA_CLASS, kp.commonPublicKeyAttributes().CKA_ID)))
		}
	}

	return retErr
}

func (kp *Pkcs11KeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	pubKey := kp.Public()
	if rsaPub, ok := pubKey.(*rsa.PublicKey); ok {
		err = rsa.VerifyPKCS1v15(rsaPub, opts.HashFunc(), digest, signature)
		return keystores.ErrorHandler(err)
	} else if eccPub, ok := pubKey.(*ecdsa.PublicKey); ok {
		if ecdsa.VerifyASN1(eccPub, digest[:], signature) {
			return nil
		} else {
			return keystores.ErrorHandler(errors.Errorf("signature validation failed"))
		}
	} else {
		return keystores.ErrorHandler(errors.Errorf("not implemented"))
	}

}

func (kp *Pkcs11KeyPair) commonPrivateKeyAttributes() *CommonPrivateKeyAttributes {
	if kp.rsaPrivKeyAttrs != nil {
		return &kp.rsaPrivKeyAttrs.CommonPrivateKeyAttributes
	} else if kp.eccPrivKeyAttrs != nil {
		return &kp.eccPrivKeyAttrs.CommonPrivateKeyAttributes
	} else {
		panic("not implemented")
	}
}

func (kp *Pkcs11KeyPair) commonPublicKeyAttributes() *CommonPublicKeyAttributes {
	if kp.rsaPubKeyAttrs != nil {
		return &kp.rsaPubKeyAttrs.CommonPublicKeyAttributes
	} else if kp.eccPubKeyAttrs != nil {
		return &kp.eccPubKeyAttrs.CommonPublicKeyAttributes
	} else {
		panic("not implemented")
	}
}
