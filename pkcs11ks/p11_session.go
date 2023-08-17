package pkcs11ks

import (
	"context"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11Session struct {
	keyStore *Pkcs11KeyStore
	ctx      *p11api.Ctx
	hSession p11api.SessionHandle
}

func (ks *Pkcs11KeyStore) aquireSession() (*Pkcs11Session, error) {
	s := &Pkcs11Session{
		keyStore: ks,
		ctx:      ks.provider.pkcs11Ctx,
	}
	var err error
	s.hSession, err = s.ctx.OpenSession(ks.slotId, p11api.CKF_SERIAL_SESSION|p11api.CKF_RW_SESSION)
	if err != nil {
		return nil, keystores.ErrorHandler(err, ks)
	}

	pin, err := ks.provider.PINAuthenticator(ks.Name(), "", false)
	if err != nil {
		return nil, keystores.ErrorHandler(err, ks)
	}

	if err = ks.provider.pkcs11Ctx.Login(s.hSession, p11api.CKU_USER, pin); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	return s, nil
}

func (ks *Pkcs11KeyStore) releaseSession(sess *Pkcs11Session) error {
	if sess.hSession == 0 {
		return keystores.ErrorHandler(keystores.ErrAlreadyClosed, ks)
	}
	err := sess.ctx.CloseSession(sess.hSession)
	if err != nil {
		return keystores.ErrorHandler(err, ks)
	}
	sess.hSession = 0
	return nil
}

type sessContext struct {
	context.Context
	sess *Pkcs11Session
}
