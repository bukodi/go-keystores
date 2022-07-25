package pkcs11ks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

type CK_OBJECT_CLASS CK_ULONG

type CommonKeyAttributes struct {
	CKA_KEY_TYPE           CK_KEY_TYPE           `p11notes:"1,5"`   // Type of key
	CKA_ID                 CK_Bytes              `p11notes:"8"`     // Key identifier for key (default empty)
	CKA_START_DATE         CK_DATE               `p11notes:"8"`     // Start date for the key (default empty)
	CKA_END_DATE           CK_DATE               `p11notes:"8"`     // End date for the key (default empty)
	CKA_DERIVE             CK_BBOOL              `p11notes:"8"`     // CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE)
	CKA_LOCAL              CK_BBOOL              `p11notes:"2,4,6"` // CK_TRUE only if key was either generated locally (i.e., on the token) with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE
	CKA_KEY_GEN_MECHANISM  CK_MECHANISM_TYPE     `p11notes:"2,4,6"` // Identifier of the mechanism used to generate the key material.
	CKA_ALLOWED_MECHANISMS CK_MECHANISM_TYPE_PTR `p11notes:""`      // pointer to a CK_MECHANISM_TYPE array A list of mechanisms allowed to be used with this key. The number of mechanisms in the array is the ulValueLen component of the attribute divided by the size of CK_MECHANISM_TYPE.
}

func addToTemplate(template []*p11api.Attribute, attrs []Attr) {
	for _, attr := range attrs {
		template = append(template, p11api.NewAttribute(attr.code, nil))
	}
}

func lookupAttrDesc(attrDesc []Attr, code uint) *Attr {
	for _, ad := range attrDesc {
		if ad.code == code {
			return &ad
		}
	}
	return nil
}

func readAttrs(p11attrs []*p11api.Attribute, destStuct any, attrDescList []Attr) error {
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
