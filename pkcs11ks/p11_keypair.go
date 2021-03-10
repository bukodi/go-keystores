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
}

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &Pkcs11KeyPair{}

func (kp *Pkcs11KeyPair) p11Ctx() (*p11api.Ctx, error) {
	// TODO: ensure open
	return kp.keySore.provider.pkcs11Ctx, nil
}

func (kp *Pkcs11KeyPair) initFields() error {

	template := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, nil),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, nil),
		p11api.NewAttribute(p11api.CKA_MODULUS, nil),
		p11api.NewAttribute(p11api.CKA_LABEL, nil),
	}

	ctx, err := kp.p11Ctx()
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}

	attrs, err := ctx.GetAttributeValue(kp.keySore.hSession, kp.hPubKey, template)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}
	rsaPubKey := rsa.PublicKey{}
	for _, a := range attrs {
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
	return nil
}

func (kp *Pkcs11KeyPair) Id() keystores.KeyPairId {
	return kp.id
}

func (kp *Pkcs11KeyPair) Label() string {
	return kp.label
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

func (kp *Pkcs11KeyPair) ExportPrivate() (der []byte, err error) {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) ExportPublic() (der []byte, err error) {
	return x509.MarshalPKIXPublicKey(kp.Public())
}

func (kp *Pkcs11KeyPair) Destroy() {
	panic("implement me")
}

func (kp *Pkcs11KeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	panic("implement me")
}
