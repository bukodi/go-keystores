package pkcs11ks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
	p11api "github.com/miekg/pkcs11"
)

func (ks *Pkcs11KeyStore) readStorageObjects() (err error) {
	if err = ks.provider.pkcs11Ctx.FindObjectsInit(ks.hSession, []*p11api.Attribute{}); err != nil {
		return keystores.ErrorHandler(err)
	}
	defer func() {
		err = ks.provider.pkcs11Ctx.FindObjectsFinal(ks.hSession)
	}()

	hObjs, _, err := ks.provider.pkcs11Ctx.FindObjects(ks.hSession, 100)
	if err != nil {
		return keystores.ErrorHandler(err)
	}

	errs := make([]error, 0)
	for _, hObj := range hObjs {
		classAttr := []*p11api.Attribute{&p11api.Attribute{p11api.CKA_CLASS, nil}}
		classAttr, err = ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, classAttr)
		if err != nil {
			errs = append(errs, keystores.ErrorHandler(err))
			continue
		}
		objClass, err := bytesTo_CK_OBJECT_CLASS(classAttr[0].Value)
		if err != nil {
			errs = append(errs, keystores.ErrorHandler(err))
			continue
		}
		switch uint(objClass) {
		case p11api.CKO_PUBLIC_KEY:
			var pubKey CommonPublicKeyAttributes
			if err := getP11Attributes(ks, hObj, &pubKey); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else if id, err := calculateKeyPairId(pubKey.CKA_PUBLIC_KEY_INFO); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else if otherPubKey := ks.knownPubKeys[id]; otherPubKey != nil {
				errs = append(errs, keystores.ErrorHandler(fmt.Errorf("non unique public key id")))
				continue
			} else {
				ks.knownPubKeys[id] = &pubKey
			}
		case p11api.CKO_PRIVATE_KEY:
			var privKey CommonPrivateKeyAttributes
			if err := getP11Attributes(ks, hObj, &privKey); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else if id, err := calculateKeyPairId(privKey.CKA_PUBLIC_KEY_INFO); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else if otherPubKey := ks.knownPubKeys[id]; otherPubKey != nil {
				errs = append(errs, keystores.ErrorHandler(fmt.Errorf("non unique public key id")))
				continue
			} else {
				ks.knownPrivKeys[id] = &privKey
			}
		default:
			var otherObj CommonStorageObjectAttributes
			if err := getP11Attributes(ks, hObj, &otherObj); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownOtherStorageObjects = append(ks.knownOtherStorageObjects, &otherObj)
			}
		}
	}

	if len(errs) == 0 {
		return nil
	} else if len(errs) == 1 {
		return errs[0]
	} else {
		multiErr := new(utils.MultiErr)
		for _, err := range errs {
			multiErr.Append(err)
		}
		return multiErr
	}
}

func getP11Attributes[T CkaStruct](ks *Pkcs11KeyStore, hObj p11api.ObjectHandle, ckaStruct T) error {
	attrTemplate, err := ckaStructToP11Attrs(ckaStruct)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	attrs, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, attrTemplate)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	err = ckaStructFromP11Attrs(ckaStruct, attrs)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return nil
}

func (ks *Pkcs11KeyStore) readRSAKeyPairs() error {
	template := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PUBLIC_KEY),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
	}

	errs := make([]error, 0)
	if err := ks.provider.pkcs11Ctx.FindObjectsInit(ks.hSession, template); err != nil {
		return keystores.ErrorHandler(err)
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

	if len(errs) == 0 {
		return nil
	} else if len(errs) == 1 {
		return errs[0]
	} else {
		multiErr := new(utils.MultiErr)
		for _, err := range errs {
			multiErr.Append(err)
		}
		return multiErr
	}
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

func calculateKeyPairId(publicKeyInfoBytes CK_Bytes) (keystores.KeyPairId, error) {
	sum := sha256.Sum256(publicKeyInfoBytes)
	return keystores.KeyPairId(hex.EncodeToString(sum[:])), nil
}
