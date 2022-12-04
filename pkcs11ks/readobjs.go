package pkcs11ks

import (
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
	p11api "github.com/miekg/pkcs11"
)

func (ks *Pkcs11KeyStore) clearInternalContainers() {
	ks.knownRSAPrivKeys = make([]*RSAPrivateKeyAttributes, 0)
	ks.knownRSAPubKeys = make([]*RSAPublicKeyAttributes, 0)
	ks.knownECCPrivKeys = make([]*ECCPrivateKeyAttributes, 0)
	ks.knownECCPubKeys = make([]*ECCPublicKeyAttributes, 0)
	ks.knownOtherStorageObjects = make([]*CommonStorageObjectAttributes, 0)

}

func (ks *Pkcs11KeyStore) readStorageObjects() (retErr error) {
	if err := keystores.EnsureOpen(ks); err != nil {
		return keystores.ErrorHandler(err)
	}
	ks.clearInternalContainers()

	// Query all object handle
	if err := ks.provider.pkcs11Ctx.FindObjectsInit(ks.hSession, []*p11api.Attribute{}); err != nil {
		return keystores.ErrorHandler(err)
	}
	defer func() {
		err := ks.provider.pkcs11Ctx.FindObjectsFinal(ks.hSession)
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
	}()

	hObjs, _, err1 := ks.provider.pkcs11Ctx.FindObjects(ks.hSession, 100)
	if err1 != nil {
		return keystores.ErrorHandler(err1)
	}

	// Loop on all objects
	for _, hObj := range hObjs {
		// Read the CKA_CLASS attribute
		var objClass uint
		if classAttr, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, []*p11api.Attribute{
			{p11api.CKA_CLASS, nil},
		}); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
			continue
		} else if objClassTyped, err := bytesTo_CK_OBJECT_CLASS(classAttr[0].Value); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
			continue
		} else {
			objClass = uint(objClassTyped)
		}

		var keyType uint
		if uint(objClass) == p11api.CKO_PUBLIC_KEY || uint(objClass) == p11api.CKO_PRIVATE_KEY {
			if classAttr, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, []*p11api.Attribute{
				{p11api.CKA_KEY_TYPE, nil},
			}); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else if keyTypeTyped, err2 := bytesTo_CK_KEY_TYPE(classAttr[0].Value); err2 != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err2))
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
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				var sensitive, extractable CK_BBOOL
				if sensitive, err = bytesTo_CK_BBOOL(attrs[0].Value); err != nil {
					retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
					continue
				}
				if extractable, err = bytesTo_CK_BBOOL(attrs[1].Value); err != nil {
					retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
					continue
				}
				skipSensitiveAttrs = bool(sensitive) && !bool(extractable)
			}
		}

		if objClass == p11api.CKO_PUBLIC_KEY && keyType == p11api.CKK_RSA {
			var pubKey RSAPublicKeyAttributes
			if err := getP11Attributes(ks, hObj, &pubKey, ks.provider.ckULONGis32bit, skipSensitiveAttrs); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownRSAPubKeys = append(ks.knownRSAPubKeys, &pubKey)
			}
		} else if objClass == p11api.CKO_PRIVATE_KEY && keyType == p11api.CKK_RSA {
			var privKey RSAPrivateKeyAttributes
			if err := getP11Attributes(ks, hObj, &privKey, ks.provider.ckULONGis32bit, skipSensitiveAttrs); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownRSAPrivKeys = append(ks.knownRSAPrivKeys, &privKey)
			}
		} else if objClass == p11api.CKO_PUBLIC_KEY && keyType == p11api.CKK_EC {
			var pubKey ECCPublicKeyAttributes
			if err := getP11Attributes(ks, hObj, &pubKey, ks.provider.ckULONGis32bit, skipSensitiveAttrs); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownECCPubKeys = append(ks.knownECCPubKeys, &pubKey)
			}
		} else if objClass == p11api.CKO_PRIVATE_KEY && keyType == p11api.CKK_EC {
			var privKey ECCPrivateKeyAttributes
			if err := getP11Attributes(ks, hObj, &privKey, ks.provider.ckULONGis32bit, skipSensitiveAttrs); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownECCPrivKeys = append(ks.knownECCPrivKeys, &privKey)
			}
		} else {
			var otherObj CommonStorageObjectAttributes
			if err := getP11Attributes(ks, hObj, &otherObj, ks.provider.ckULONGis32bit, skipSensitiveAttrs); err != nil {
				retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
				continue
			} else {
				ks.knownOtherStorageObjects = append(ks.knownOtherStorageObjects, &otherObj)
			}
		}
	}

	return
}

func getP11Attributes[T CkaStruct](ks *Pkcs11KeyStore, hObj p11api.ObjectHandle, ckaStruct T, ckULONGIs32bit bool, skipSensitiveAttrs bool) error {
	attrTemplate, err := ckaStructToP11Attrs(ckaStruct, ckULONGIs32bit, skipSensitiveAttrs)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	attrs, err := ks.provider.pkcs11Ctx.GetAttributeValue(ks.hSession, hObj, attrTemplate)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	err = ckaStructFromP11Attrs(ckaStruct, attrs, ckULONGIs32bit)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return nil
}
