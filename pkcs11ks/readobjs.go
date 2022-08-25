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
	if err = keystores.EnsureOpen(ks); err != nil {
		return keystores.ErrorHandler(err)
	}
	if err = ks.provider.pkcs11Ctx.FindObjectsInit(ks.hSession, []*p11api.Attribute{}); err != nil {
		return keystores.ErrorHandler(err)
	}
	defer func() {
		finErr := ks.provider.pkcs11Ctx.FindObjectsFinal(ks.hSession)
		if finErr != nil {
			finErr = keystores.ErrorHandler(finErr)
			if err == nil {
				err = finErr
			} else if multiErr, ok := err.(*utils.MultiErr); ok {
				multiErr.Append(finErr)
			} else {
				multiErr = utils.NewMultiErr()
				multiErr.Append(err)
				multiErr.Append(finErr)
				err = multiErr
			}
		}
	}()

	hObjs, _, err := ks.provider.pkcs11Ctx.FindObjects(ks.hSession, 100)
	if err != nil {
		return keystores.ErrorHandler(err)
	}

	errs := make([]error, 0)
	for _, hObj := range hObjs {
		var objClass uint
		if classAttr, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, []*p11api.Attribute{
			{p11api.CKA_CLASS, nil},
		}); err != nil {
			errs = append(errs, keystores.ErrorHandler(err))
			continue
		} else if objClassTyped, err := bytesTo_CK_OBJECT_CLASS(classAttr[0].Value); err != nil {
			errs = append(errs, keystores.ErrorHandler(err))
			continue
		} else {
			objClass = uint(objClassTyped)
		}

		var keyType uint
		if uint(objClass) == p11api.CKO_PUBLIC_KEY || uint(objClass) == p11api.CKO_PRIVATE_KEY {
			if classAttr, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, []*p11api.Attribute{
				{p11api.CKA_KEY_TYPE, nil},
			}); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else if keyTypeTyped, err := bytesTo_CK_KEY_TYPE(classAttr[0].Value); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				keyType = uint(keyTypeTyped)
			}
		}

		var skipSensitiveAttrs bool
		if uint(objClass) == p11api.CKO_PRIVATE_KEY || uint(objClass) == p11api.CKO_SECRET_KEY {
			if attrs, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, []*p11api.Attribute{
				{p11api.CKA_SENSITIVE, nil},
				{p11api.CKA_EXTRACTABLE, nil},
			}); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				var sensitive, extractable CK_BBOOL
				if sensitive, err = bytesTo_CK_BBOOL(attrs[0].Value); err != nil {
					errs = append(errs, keystores.ErrorHandler(err))
					continue
				}
				if extractable, err = bytesTo_CK_BBOOL(attrs[1].Value); err != nil {
					errs = append(errs, keystores.ErrorHandler(err))
					continue
				}
				skipSensitiveAttrs = bool(sensitive) && !bool(extractable)
			}
		}

		if objClass == p11api.CKO_PUBLIC_KEY && keyType == p11api.CKK_RSA {
			var pubKey RSAPublicKeyAttributes
			if err := getP11Attributes(ks, hObj, &pubKey, skipSensitiveAttrs); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownRSAPubKeys = append(ks.knownRSAPubKeys, &pubKey)
			}
		} else if objClass == p11api.CKO_PRIVATE_KEY && keyType == p11api.CKK_RSA {
			var privKey RSAPrivateKeyAttributes
			if err := getP11Attributes(ks, hObj, &privKey, skipSensitiveAttrs); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownRSAPrivKeys = append(ks.knownRSAPrivKeys, &privKey)
			}
		} else if objClass == p11api.CKO_PUBLIC_KEY && keyType == p11api.CKK_EC {
			var pubKey ECCPublicKeyAttributes
			if err := getP11Attributes(ks, hObj, &pubKey, skipSensitiveAttrs); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownECPubKeys = append(ks.knownECPubKeys, &pubKey)
			}
		} else if objClass == p11api.CKO_PRIVATE_KEY && keyType == p11api.CKK_EC {
			var privKey ECCPrivateKeyAttributes
			if err := getP11Attributes(ks, hObj, &privKey, skipSensitiveAttrs); err != nil {
				errs = append(errs, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownECPrivKeys = append(ks.knownECPrivKeys, &privKey)
			}
		} else {
			var otherObj CommonStorageObjectAttributes
			if err := getP11Attributes(ks, hObj, &otherObj, skipSensitiveAttrs); err != nil {
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

func getP11Attributes[T CkaStruct](ks *Pkcs11KeyStore, hObj p11api.ObjectHandle, ckaStruct T, skipSensitiveAttrs bool) error {
	attrTemplate, err := ckaStructToP11Attrs(ckaStruct, skipSensitiveAttrs)
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
