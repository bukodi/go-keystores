package pkcs11ks

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"io"
	"math/big"
)

type Pkcs11KeyPair struct {
	keySore     *Pkcs11KeyStore
	hPubKey     p11api.ObjectHandle
	hPrivKey    p11api.ObjectHandle
	pubKey      crypto.PublicKey
	id          keystores.KeyPairId
	keyAlorithm keystores.KeyAlgorithm
	label       string
	keyUsage    x509.KeyUsage

	PublicKeyAttributes  *CommonPublicKeyAttributes
	PrivateKeyAttributes *CommonPrivateKeyAttributes
}

func (kp *Pkcs11KeyPair) SetLabel(label string) error {
	//TODO implement me
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Attestation(nonce []byte) (att keystores.Attestation, err error) {
	//TODO implement me
	panic("implement me")
}

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &Pkcs11KeyPair{}

func (kp *Pkcs11KeyPair) p11CtxWithSess() (*p11api.Ctx, p11api.SessionHandle, error) {
	// TODO: ensure open
	return kp.keySore.provider.pkcs11Ctx, kp.keySore.hSession, nil
}

func (kp *Pkcs11KeyPair) initFields() error {

	pubTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, nil),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, nil),
		p11api.NewAttribute(p11api.CKA_MODULUS, nil),
		p11api.NewAttribute(p11api.CKA_LABEL, nil),
	}

	p11ctx, sess, err := kp.p11CtxWithSess()
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}

	pubAttrs, err := p11ctx.GetAttributeValue(sess, kp.hPubKey, pubTemplate)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}
	rsaPubKey := rsa.PublicKey{}
	for _, a := range pubAttrs {
		switch a.Type {
		case p11api.CKA_MODULUS:
			rsaPubKey.N = big.NewInt(0)
			rsaPubKey.N.SetBytes(a.Value)
		case p11api.CKA_PUBLIC_EXPONENT:
			bigExponent := big.NewInt(0)
			bigExponent.SetBytes(a.Value)
			rsaPubKey.E = int(bigExponent.Uint64())
		case p11api.CKA_LABEL:
			kp.label = string(a.Value)
		}
	}

	kp.pubKey = &rsaPubKey
	kp.id, err = keystores.GenerateKeyPairIdFromPubKey(kp.pubKey)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}

	privTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_SIGN, nil),
		p11api.NewAttribute(p11api.CKA_DECRYPT, nil),
		p11api.NewAttribute(p11api.CKA_UNWRAP, nil),
		p11api.NewAttribute(p11api.CKA_DERIVE, nil),
	}
	privAttrs, err := p11ctx.GetAttributeValue(kp.keySore.hSession, kp.hPrivKey, privTemplate)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}
	for _, a := range privAttrs {
		switch a.Type {
		case p11api.CKA_SIGN:
			if a.Value[0] != 0 {
				kp.keyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign
			}
		case p11api.CKA_DECRYPT:
			if a.Value[0] != 0 {
				kp.keyUsage |= x509.KeyUsageDataEncipherment
			}
		case p11api.CKA_UNWRAP:
			if a.Value[0] != 0 {
				kp.keyUsage |= x509.KeyUsageKeyEncipherment
			}
		case p11api.CKA_DERIVE:
			if a.Value[0] != 0 {
				kp.keyUsage |= x509.KeyUsageKeyAgreement
			}
		}
	}

	return nil
}

func (kp *Pkcs11KeyPair) Id() keystores.KeyPairId {
	return kp.id
}

func (kp *Pkcs11KeyPair) Label() string {
	return kp.label
}

func (kp *Pkcs11KeyPair) KeyUsage() x509.KeyUsage {
	return kp.keyUsage
}

func (kp *Pkcs11KeyPair) Algorithm() keystores.KeyAlgorithm {
	return kp.keyAlorithm
}

func (kp *Pkcs11KeyPair) KeyStore() keystores.KeyStore {
	return kp.keySore
}

func (kp *Pkcs11KeyPair) Public() crypto.PublicKey {
	return kp.pubKey
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

func (kp *Pkcs11KeyPair) Destroy() error {
	ctx, sess, err := kp.p11CtxWithSess()
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}

	err = ctx.DestroyObject(sess, kp.hPrivKey)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}

	err = ctx.DestroyObject(sess, kp.hPubKey)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}
	return nil
}

func (kp *Pkcs11KeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	panic("implement me")
}
