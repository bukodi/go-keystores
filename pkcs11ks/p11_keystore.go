package pkcs11ks

import (
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11KeyStore struct {
	provider  *Pkcs11Provider
	slotId    uint
	tokenInfo *p11api.TokenInfo
	slotInfo  *p11api.SlotInfo
	hSession  p11api.SessionHandle
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &Pkcs11KeyStore{}

func (ks *Pkcs11KeyStore) Id() string {
	return ks.tokenInfo.SerialNumber
}

func (ks *Pkcs11KeyStore) Name() string {
	return ks.tokenInfo.Label
}

func (ks *Pkcs11KeyStore) Open() error {
	if ks.hSession != 0 {
		return keystores.ErrorHandler(keystores.ErrAlreadyOpen)
	}
	err := keystores.EnsureOpen(ks.provider)
	if err != nil {
		return keystores.ErrorHandler(err)
	}

	hSess, err := ks.provider.pkcs11Ctx.OpenSession(ks.slotId, p11api.CKF_SERIAL_SESSION|p11api.CKF_RW_SESSION)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	var pin = "1234" // TODO use callback
	if err = ks.provider.pkcs11Ctx.Login(hSess, p11api.CKU_USER, pin); err != nil {
		return keystores.ErrorHandler(err)
	}
	ks.hSession = hSess
	return nil
}

func (ks *Pkcs11KeyStore) Close() error {
	if ks.hSession == 0 {
		return keystores.ErrorHandler(keystores.ErrAlreadyClosed)
	}
	err := ks.provider.pkcs11Ctx.Logout(ks.hSession)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	err = ks.provider.pkcs11Ctx.CloseSession(ks.hSession)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	ks.hSession = 0
	return nil
}

func (ks *Pkcs11KeyStore) IsOpen() bool {
	return ks.hSession != 0
}

func (ks *Pkcs11KeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{keystores.KeyAlgRSA2048, keystores.KeyAlgECP256}
	return algs
}

func (ks *Pkcs11KeyStore) KeyPairs() []keystores.KeyPair {
	panic("implement me")
}

func (ks *Pkcs11KeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	tokenPersistent := !opts.Ephemeral
	kuSign := (opts.KeyUsage & (x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature)) != 0
	publicKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PUBLIC_KEY),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_VERIFY, kuSign),
		p11api.NewAttribute(p11api.CKA_ENCRYPT, opts.KeyUsage&x509.KeyUsageDataEncipherment != 0),
		p11api.NewAttribute(p11api.CKA_WRAP, opts.KeyUsage&x509.KeyUsageKeyEncipherment != 0),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, 2048),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
	}
	privateKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_SIGN, kuSign),
		p11api.NewAttribute(p11api.CKA_DECRYPT, opts.KeyUsage&x509.KeyUsageDataEncipherment != 0),
		p11api.NewAttribute(p11api.CKA_UNWRAP, opts.KeyUsage&x509.KeyUsageKeyEncipherment != 0),
		p11api.NewAttribute(p11api.CKA_DERIVE, opts.KeyUsage&x509.KeyUsageKeyAgreement != 0),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
		p11api.NewAttribute(p11api.CKA_SENSITIVE, !opts.Exportable),
		p11api.NewAttribute(p11api.CKA_EXTRACTABLE, opts.Exportable),
	}

	mech := p11api.NewMechanism(p11api.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)

	pbk, pvk, err := ks.provider.pkcs11Ctx.GenerateKeyPair(ks.hSession,
		[]*p11api.Mechanism{mech},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp := Pkcs11KeyPair{
		keySore:  ks,
		hPubKey:  pbk,
		hPrivKey: pvk,
	}
	err = kp.initFields()
	if err != nil {
		kp.Destroy()
		return nil, keystores.ErrorHandler(err)
	}
	return &kp, nil
}

func (ks *Pkcs11KeyStore) ImportKeyPair(der []byte) (kp keystores.KeyPair, err error) {
	panic("implement me")
}
