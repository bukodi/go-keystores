package pkcs11ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
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

func (kp *Pkcs11KeyPair) Public() crypto.PublicKey {
	if kp.rsaPublicKey != nil {
		return kp.rsaPublicKey
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

func (kp *Pkcs11KeyPair) KeyUsage() x509.KeyUsage {
	var ku x509.KeyUsage
	if kp.commonPrivateKeyAttributes().CKA_SIGN {
		ku = ku | x509.KeyUsageDigitalSignature
	}
	if kp.commonPrivateKeyAttributes().CKA_DECRYPT {
		ku = ku | x509.KeyUsageDataEncipherment
	}
	if kp.commonPrivateKeyAttributes().CKA_UNWRAP {
		ku = ku | x509.KeyUsageKeyEncipherment
	}
	if kp.commonPrivateKeyAttributes().CKA_DERIVE {
		ku = ku | x509.KeyUsageKeyAgreement
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
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) ExportPrivate() (privKey crypto.PrivateKey, err error) {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Destroy() (retErr error) {
	if err := keystores.EnsureOpen(kp.keyStore); err != nil {
		return keystores.ErrorHandler(err)
	}

	if cntDelete, err := kp.keyStore.destroyObject(kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID, ""); err != nil {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
	} else if cntDelete > 1 {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("more than one object with (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID)))
	} else if cntDelete == 0 {
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(errors.Errorf("private key not deleted (CKA_CLASS=%v and CKA_ID=%v)", kp.commonPrivateKeyAttributes().CKA_CLASS, kp.commonPrivateKeyAttributes().CKA_ID)))
	}

	if kp.commonPublicKeyAttributes() != nil {
		if cntDelete, err := kp.keyStore.destroyObject(kp.commonPublicKeyAttributes().CKA_CLASS, kp.commonPublicKeyAttributes().CKA_ID, ""); err != nil {
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
	panic("implement me")
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
