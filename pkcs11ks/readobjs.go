package pkcs11ks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

func (ks *Pkcs11KeyStore) readRSAKeyPairs(kpArray []*Pkcs11KeyPair, errs []error) {
	template := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PUBLIC_KEY),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
	}

	if err := ks.provider.pkcs11Ctx.FindObjectsInit(ks.hSession, template); err != nil {
		errs = append(errs, keystores.ErrorHandler(err))
		return
	}
	defer func() {
		err := ks.provider.pkcs11Ctx.FindObjectsFinal(ks.hSession)
		if err != nil {
			if errs == nil {
				errs = []error{}
			}
			errs = append(errs, keystores.ErrorHandler(err))
		}
	}()

	if hObjs, _, err := ks.provider.pkcs11Ctx.FindObjects(ks.hSession, 100); err != nil {
		errs = append(errs, keystores.ErrorHandler(err))
	} else {
		for _, hObj := range hObjs {
			p11Kp, err := ks.readKeypair(hObj)
			if err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
			} else {
				ks.knownKeyPairs = append(ks.knownKeyPairs, p11Kp)
			}
		}
	}

	return
}

func (ks *Pkcs11KeyStore) readRSAKeyPair(hPubKey p11api.ObjectHandle) (*Pkcs11KeyPair, error) {
	template := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, nil),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, nil),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, nil),
		p11api.NewAttribute(p11api.CKA_MODULUS, nil),
		p11api.NewAttribute(p11api.CKA_LABEL, nil),
	}
	attrs, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hPubKey, template)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp := Pkcs11KeyPair{}

	for _, attr := range attrs {
		switch attr.Type {
		case p11api.CKA_CLASS:
		case p11api.CKA_KEY_TYPE:
		case p11api.CKA_PUBLIC_EXPONENT:
		case p11api.CKA_MODULUS_BITS:
		case p11api.CKA_MODULUS:
		case p11api.CKA_LABEL:
			kp.label = string(attr.Value)
		default:
			fmt.Printf("Unknown attribute: %d", attr.Type)
		}
	}

	return &kp, nil

}
