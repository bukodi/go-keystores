package pkcs11ks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"reflect"
	"time"
)

type CK_OBJECT_CLASS CK_ULONG

type CkaStruct interface {
	*CommonStorageObjectAttributes | *CommonKeyAttributes | *CommonPublicKeyAttributes | *CommonPrivateKeyAttributes
}

type CommonStorageObjectAttributes struct {
	CKA_TOKEN       CK_BBOOL  // CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE.
	CKA_PRIVATE     CK_BBOOL  // CK_TRUE if object is a private object; CK_FALSE if object is a public object.  Default value is token-specific, and may depend on the values of other attributes of the object.
	CKA_MODIFIABLE  CK_BBOOL  // CK_TRUE if object can be modified Default is CK_TRUE.
	CKA_LABEL       CK_String // Description of the object (default empty).
	CKA_COPYABLE    CK_BBOOL  // CK_TRUE if object can be copied using C_CopyObject. Defaults to CK_TRUE. Can’t be set to TRUE once it is set to FALSE.
	CKA_DESTROYABLE CK_BBOOL  // CK_TRUE if the object can be destroyed using C_DestroyObject.  Default is CK_TRUE.
}

func (csoa *CommonStorageObjectAttributes) getP11Attrs() ([]*p11api.Attribute, error) {
	p11Attrs := make([]*p11api.Attribute, 0)
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_TOKEN, bytesFrom_CK_BBOOL(csoa.CKA_TOKEN)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_PRIVATE, bytesFrom_CK_BBOOL(csoa.CKA_PRIVATE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_MODIFIABLE, bytesFrom_CK_BBOOL(csoa.CKA_MODIFIABLE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_LABEL, bytesFrom_CK_String(csoa.CKA_LABEL)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_COPYABLE, bytesFrom_CK_BBOOL(csoa.CKA_COPYABLE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_DESTROYABLE, bytesFrom_CK_BBOOL(csoa.CKA_DESTROYABLE)})
	return p11Attrs, nil
}

func (csoa *CommonStorageObjectAttributes) setP11Attrs(p11Attrs map[uint]*p11api.Attribute) error {
	var err error
	if csoa.CKA_TOKEN, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_TOKEN].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_TOKEN)
	}
	if csoa.CKA_PRIVATE, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_PRIVATE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_PRIVATE)
	}
	if csoa.CKA_MODIFIABLE, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_MODIFIABLE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_MODIFIABLE)
	}
	if csoa.CKA_LABEL, err = bytesTo_CK_String(p11Attrs[p11api.CKA_LABEL].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_LABEL)
	}
	if csoa.CKA_COPYABLE, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_COPYABLE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_COPYABLE)
	}
	if csoa.CKA_DESTROYABLE, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_DESTROYABLE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_DESTROYABLE)
	}
	return nil
}

type CommonKeyAttributes struct {
	CommonStorageObjectAttributes
	CKA_KEY_TYPE           CK_KEY_TYPE           // Type of key
	CKA_ID                 CK_Bytes              // Key identifier for key (default empty)
	CKA_START_DATE         CK_DATE               // Start date for the key (default empty)
	CKA_END_DATE           CK_DATE               // End date for the key (default empty)
	CKA_DERIVE             CK_BBOOL              // CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE)
	CKA_LOCAL              CK_BBOOL              // CK_TRUE only if key was either generated locally (i.e., on the token) with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE
	CKA_KEY_GEN_MECHANISM  CK_MECHANISM_TYPE     // Identifier of the mechanism used to generate the key material.
	CKA_ALLOWED_MECHANISMS CK_MECHANISM_TYPE_PTR // pointer to a CK_MECHANISM_TYPE array A list of mechanisms allowed to be used with this key. The number of mechanisms in the array is the ulValueLen component of the attribute divided by the size of CK_MECHANISM_TYPE.
}

func (cka *CommonKeyAttributes) getP11Attrs() ([]*p11api.Attribute, error) {
	p11Attrs, err := cka.CommonStorageObjectAttributes.getP11Attrs()
	if err != nil {
		return p11Attrs, err
	}
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_KEY_TYPE, bytesFrom_CK_KEY_TYPE(cka.CKA_KEY_TYPE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_ID, bytesFrom_CK_Bytes(cka.CKA_ID)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_START_DATE, bytesFrom_CK_DATE(cka.CKA_END_DATE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_END_DATE, bytesFrom_CK_DATE(cka.CKA_END_DATE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_DERIVE, bytesFrom_CK_BBOOL(cka.CKA_DERIVE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_LOCAL, bytesFrom_CK_BBOOL(cka.CKA_LOCAL)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_KEY_GEN_MECHANISM, bytesFrom_CK_MECHANISM_TYPE(cka.CKA_KEY_GEN_MECHANISM)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_ALLOWED_MECHANISMS, bytesFrom_CK_MECHANISM_TYPE_PTR(cka.CKA_ALLOWED_MECHANISMS)})
	return p11Attrs, nil
}

func (cka *CommonKeyAttributes) setP11Attrs(p11Attrs map[uint]*p11api.Attribute) error {
	err := cka.CommonStorageObjectAttributes.setP11Attrs(p11Attrs)
	if err != nil {
		return err
	}
	if cka.CKA_KEY_TYPE, err = bytesTo_CK_KEY_TYPE(p11Attrs[p11api.CKA_KEY_TYPE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_KEY_TYPE)
	}
	if cka.CKA_ID, err = bytesTo_CK_Bytes(p11Attrs[p11api.CKA_ID].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_ID)
	}
	if cka.CKA_START_DATE, err = bytesTo_CK_DATE(p11Attrs[p11api.CKA_START_DATE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_START_DATE)
	}
	if cka.CKA_END_DATE, err = bytesTo_CK_DATE(p11Attrs[p11api.CKA_END_DATE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_END_DATE)
	}
	if cka.CKA_DERIVE, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_DERIVE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_DERIVE)
	}
	if cka.CKA_LOCAL, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_LOCAL].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_LOCAL)
	}
	if cka.CKA_KEY_GEN_MECHANISM, err = bytesTo_CK_MECHANISM_TYPE(p11Attrs[p11api.CKA_KEY_GEN_MECHANISM].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_KEY_GEN_MECHANISM)
	}
	if cka.CKA_ALLOWED_MECHANISMS, err = bytesTo_CK_MECHANISM_TYPE_PTR(p11Attrs[p11api.CKA_ALLOWED_MECHANISMS].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_ALLOWED_MECHANISMS)
	}
	return nil
}

type CommonPublicKeyAttributes struct {
	CommonKeyAttributes
	CKA_SUBJECT         CK_Bytes         // DER-encoding of the key subject name (default empty)
	CKA_ENCRYPT         CK_BBOOL         // CK_TRUE if key supports encryption
	CKA_VERIFY          CK_BBOOL         // CK_TRUE if key supports verification where the signature is an appendix to the data
	CKA_VERIFY_RECOVER  CK_BBOOL         // CK_TRUE if key supports verification where the data is recovered from the signature
	CKA_WRAP            CK_BBOOL         // CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
	CKA_TRUSTED         CK_BBOOL         // The key can be trusted for the application that it was created. The wrapping key can be used to wrap keys with  CKA_WRAP_WITH_TRUSTED set to CK_TRUE.
	CKA_WRAP_TEMPLATE   CK_ATTRIBUTE_PTR // For wrapping keys. The attribute template to match against any keys wrapped using this wrapping key. Keys that do not match cannot be wrapped. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.
	CKA_PUBLIC_KEY_INFO CK_Bytes         // DER-encoding of the SubjectPublicKeyInfo for this public key.  (MAY be empty, DEFAULT derived from the underlying public key data)
}

func (cpubka *CommonPublicKeyAttributes) getP11Attrs() ([]*p11api.Attribute, error) {
	p11Attrs, err := cpubka.CommonKeyAttributes.getP11Attrs()
	if err != nil {
		return p11Attrs, err
	}
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_SUBJECT, bytesFrom_CK_Bytes(cpubka.CKA_SUBJECT)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_ENCRYPT, bytesFrom_CK_BBOOL(cpubka.CKA_ENCRYPT)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_VERIFY, bytesFrom_CK_BBOOL(cpubka.CKA_VERIFY)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_VERIFY_RECOVER, bytesFrom_CK_BBOOL(cpubka.CKA_VERIFY_RECOVER)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_WRAP, bytesFrom_CK_BBOOL(cpubka.CKA_WRAP)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_TRUSTED, bytesFrom_CK_BBOOL(cpubka.CKA_TRUSTED)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_WRAP_TEMPLATE, bytesFrom_CK_ATTRIBUTE_PTR(cpubka.CKA_WRAP_TEMPLATE)})
	p11Attrs = append(p11Attrs, &p11api.Attribute{p11api.CKA_PUBLIC_KEY_INFO, bytesFrom_CK_Bytes(cpubka.CKA_PUBLIC_KEY_INFO)})
	return p11Attrs, nil
}

func (cpubka *CommonPublicKeyAttributes) setP11Attrs(p11Attrs map[uint]*p11api.Attribute) error {
	err := cpubka.CommonKeyAttributes.setP11Attrs(p11Attrs)
	if err != nil {
		return err
	}
	if cpubka.CKA_SUBJECT, err = bytesTo_CK_Bytes(p11Attrs[p11api.CKA_SUBJECT].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_SUBJECT)
	}
	if cpubka.CKA_ENCRYPT, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_ENCRYPT].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_ENCRYPT)
	}
	if cpubka.CKA_VERIFY, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_VERIFY].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_VERIFY)
	}
	if cpubka.CKA_VERIFY_RECOVER, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_VERIFY_RECOVER].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_VERIFY_RECOVER)
	}
	if cpubka.CKA_WRAP, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_WRAP].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_WRAP)
	}
	if cpubka.CKA_TRUSTED, err = bytesTo_CK_BBOOL(p11Attrs[p11api.CKA_TRUSTED].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_TRUSTED)
	}
	if cpubka.CKA_WRAP_TEMPLATE, err = bytesTo_CK_ATTRIBUTE_PTR(p11Attrs[p11api.CKA_WRAP_TEMPLATE].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_WRAP_TEMPLATE)
	}
	if cpubka.CKA_PUBLIC_KEY_INFO, err = bytesTo_CK_Bytes(p11Attrs[p11api.CKA_PUBLIC_KEY_INFO].Value); err != nil {
		return err
	} else {
		delete(p11Attrs, p11api.CKA_PUBLIC_KEY_INFO)
	}

	return nil
}

type CommonPrivateKeyAttributes struct {
	CommonKeyAttributes
	CKA_SUBJECT             CK_Bytes         // DER-encoding of certificate subject name (default empty)
	CKA_SENSITIVE           CK_BBOOL         // CK_TRUE if key is sensitive
	CKA_DECRYPT             CK_BBOOL         // CK_TRUE if key supports decryption
	CKA_SIGN                CK_BBOOL         // CK_TRUE if key supports signatures where the signature is an appendix to the data
	CKA_SIGN_RECOVER        CK_BBOOL         // CK_TRUE if key supports signatures where the data can be recovered from the signature
	CKA_UNWRAP              CK_BBOOL         // CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)
	CKA_EXTRACTABLE         CK_BBOOL         // CK_TRUE if key is extractable and can be wrapped
	CKA_ALWAYS_SENSITIVE    CK_BBOOL         // CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE
	CKA_NEVER_EXTRACTABLE   CK_BBOOL         // CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE
	CKA_WRAP_WITH_TRUSTED   CK_BBOOL         // CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
	CKA_UNWRAP_TEMPLATE     CK_ATTRIBUTE_PTR // For wrapping keys. The attribute template to apply to any keys unwrapped using this wrapping key. Any user supplied template is applied after this template as if the object has already been created. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.
	CKA_ALWAYS_AUTHENTICATE CK_BBOOL         // If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE.
	CKA_PUBLIC_KEY_INFO     CK_Bytes         // DER-encoding of the SubjectPublicKeyInfo for the associated public key (MAY be empty; DEFAULT derived from the underlying private key data; MAY be manually set for specific key types; if set; MUST be consistent with the underlying private key data)
}

func ckaStructToP11Attrs[T CkaStruct](ckaStruct T) ([]*p11api.Attribute, error) {
	p11Attrs := make([]*p11api.Attribute, 0)

	pv := reflect.ValueOf(ckaStruct)
	err := processCkaFields(pv, func(v reflect.Value, ckaDesc *CkaDesc) error {
		bytes, err := ckValueWriteToBytes(v)
		if err != nil {
			return err
		}

		var p11Attr p11api.Attribute
		p11Attr.Value = bytes
		p11Attr.Type = ckaDesc.code
		p11Attrs = append(p11Attrs, &p11Attr)
		return nil
	})
	return p11Attrs, err
}

func ckaStructFromP11Attrs[T CkaStruct](ckaStruct T, p11Attrs []*p11api.Attribute) error {
	unprocessedStructFields := make([]*CkaDesc, 0)
	p11AttrsByCode := make(map[uint]*p11api.Attribute)
	for _, a := range p11Attrs {
		p11AttrsByCode[a.Type] = a
	}

	pv := reflect.ValueOf(ckaStruct)
	err := processCkaFields(pv, func(v reflect.Value, ckaDesc *CkaDesc) error {
		p11Attr := p11AttrsByCode[ckaDesc.code]
		if p11Attr == nil {
			unprocessedStructFields = append(unprocessedStructFields, ckaDesc)
			return nil
		} else {
			delete(p11AttrsByCode, ckaDesc.code)
		}

		err := ckValueSetFromBytes(p11Attr.Value, v)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

var ckDateType = reflect.TypeOf(CK_DATE(time.Time{}))

func processCkaFields(pv reflect.Value, fn func(reflect.Value, *CkaDesc) error) error {
	sv := pv.Elem()
	if sv.Kind() != reflect.Struct {
		return fmt.Errorf("argument is not a pointer to a struct")
	}

	st := sv.Type()

	for i := 0; i < st.NumField(); i++ {
		structField := st.Field(i)
		fieldValue := sv.FieldByName(structField.Name)
		if structField.Type.Kind() == reflect.Struct && ckDateType != structField.Type {
			if err := processCkaFields(fieldValue.Addr(), fn); err != nil {
				return err
			}
			continue
		}

		// At this point field name begins with CKA_ and type begins with CK_
		ckaDesc := CkaDescByName(structField.Name)
		err := fn(fieldValue, ckaDesc)
		if err != nil {
			return err
		}
	}

	return nil
}

func addToTemplate(template []*p11api.Attribute, attrs []CkaDesc) {
	for _, attr := range attrs {
		template = append(template, p11api.NewAttribute(attr.code, nil))
	}
}

func lookupAttrDesc(attrDesc []CkaDesc, code uint) *CkaDesc {
	for _, ad := range attrDesc {
		if ad.code == code {
			return &ad
		}
	}
	return nil
}

func readAttrs(p11attrs []*p11api.Attribute, destStuct any, attrDescList []CkaDesc) error {
	for _, p11attr := range p11attrs {
		attrDesc := lookupAttrDesc(attrDescList, p11attr.Type)
		if attrDesc == nil {
			return keystores.ErrorHandler(fmt.Errorf("unknown CKA: %d", p11attr.Type))
		}

		//attr := attrs[p11attr.Type]
		//if attr == nil {
		//	continue
		//}
		//
		//value, err := attr.read(p11attr.Value)
		//if err != nil {
		//	return keystores.ErrorHandler(fmt.Errorf("cna't read attr: %d", p11attr.Type))
		//}
		//_ = value
	}
	return nil
}

type RSAPublicKeyObjectAttributes struct {
}
