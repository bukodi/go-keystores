package pkcs11ks

import (
	p11api "github.com/miekg/pkcs11"
	"reflect"
	"time"
)

type note uint

type CkaDesc struct {
	groupName string
	valueType reflect.Type
	name      string
	code      uint
	notes     []note
	desc      string
}

func init() {
	registerCkaDesc("CommonStorageObjectAttributes", []*CkaDesc{
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_TOKEN", p11api.CKA_TOKEN, []note{}, `CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE.`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_PRIVATE", p11api.CKA_PRIVATE, []note{}, `CK_TRUE if object is a private object; CK_FALSE if object is a public object.  Default value is token-specific, and may depend on the values of other attributes of the object.`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_MODIFIABLE", p11api.CKA_MODIFIABLE, []note{}, `CK_TRUE if object can be modified Default is CK_TRUE.`},
		{"", reflect.TypeOf(CK_String("")), "CKA_LABEL", p11api.CKA_LABEL, []note{}, `Description of the object (default empty).`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_COPYABLE", p11api.CKA_COPYABLE, []note{}, `CK_TRUE if object can be copied using C_CopyObject. Defaults to CK_TRUE. Can’t be set to TRUE once it is set to FALSE.`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_DESTROYABLE", p11api.CKA_DESTROYABLE, []note{}, `CK_TRUE if the object can be destroyed using C_DestroyObject.  Default is CK_TRUE.`},
	})

	registerCkaDesc("CommonKeyAttributes", []*CkaDesc{
		{"", reflect.TypeOf(CK_KEY_TYPE(0)), "CKA_KEY_TYPE", p11api.CKA_KEY_TYPE, []note{1, 5}, `Type of key`},
		{"", reflect.TypeOf(CK_Bytes(nil)), "CKA_ID", p11api.CKA_ID, []note{8}, ` Key identifier for key (default empty)`},
		{"", reflect.TypeOf(CK_DATE(time.Time{})), "CKA_START_DATE", p11api.CKA_START_DATE, []note{8}, ` Start date for the key (default empty)`},
		{"", reflect.TypeOf(CK_DATE(time.Time{})), "CKA_END_DATE", p11api.CKA_END_DATE, []note{8}, ` End date for the key (default empty)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_DERIVE", p11api.CKA_DERIVE, []note{8}, ` CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_LOCAL", p11api.CKA_LOCAL, []note{2, 4, 6}, ` CK_TRUE only if key was either (a.) generated locally (i.e., on the token) with a C_GenerateKey or C_GenerateKeyPair call (b.) created with a C_CopyObject call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE`},
		{"", reflect.TypeOf(CK_MECHANISM_TYPE(0)), "CKA_KEY_GEN_MECHANISM", p11api.CKA_KEY_GEN_MECHANISM, []note{2, 4, 6}, ` Identifier of the mechanism used to generate the key material.`},
		{"", reflect.TypeOf(CK_MECHANISM_TYPE_PTR([]CK_MECHANISM_TYPE{})), "CKA_ALLOWED_MECHANISMS", p11api.CKA_ALLOWED_MECHANISMS, []note{}, ` pointer to a CK_MECHANISM_TYPE array A list of mechanisms allowed to be used with this key. The number of mechanisms in the array is the ulValueLen component of the attribute divided by the size of CK_MECHANISM_TYPE.`},
	})

	registerCkaDesc("CommonPublicKeyAttributes", []*CkaDesc{
		{"", reflect.TypeOf(CK_Bytes([]byte{})), "CKA_SUBJECT", p11api.CKA_SUBJECT, []note{8}, ` DER-encoding of the key subject name (default empty)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_ENCRYPT", p11api.CKA_ENCRYPT, []note{8, 9}, ` CK_TRUE if key supports encryption`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_VERIFY", p11api.CKA_VERIFY, []note{8, 9}, ` CK_TRUE if key supports verification where the signature is an appendix to the data`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_VERIFY_RECOVER", p11api.CKA_VERIFY_RECOVER, []note{8, 9}, ` CK_TRUE if key supports verification where the data is recovered from the signature`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_WRAP", p11api.CKA_WRAP, []note{8, 9}, ` CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_TRUSTED", p11api.CKA_TRUSTED, []note{10}, ` The key can be trusted for the application that it was created. The wrapping key can be used to wrap keys with  CKA_WRAP_WITH_TRUSTED set to CK_TRUE.`},
		{"", reflect.TypeOf(CK_ATTRIBUTE_PTR([]byte{})), "CKA_WRAP_TEMPLATE", p11api.CKA_WRAP_TEMPLATE, []note{}, ` For wrapping keys. The attribute template to match against any keys wrapped using this wrapping key. Keys that do not match cannot be wrapped. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.`},
		{"", reflect.TypeOf(CK_Bytes([]byte{})), "CKA_PUBLIC_KEY_INFO", p11api.CKA_PUBLIC_KEY_INFO, []note{}, ` DER-encoding of the SubjectPublicKeyInfo for this public key.  (MAY be empty, DEFAULT derived from the underlying public key data)`},
	})

	registerCkaDesc("CommonPrivateKeyAttributes", []*CkaDesc{
		{"", reflect.TypeOf(CK_Bytes([]byte{})), "CKA_SUBJECT", p11api.CKA_SUBJECT, []note{8}, ` DER-encoding of certificate subject name (default empty)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_SENSITIVE", p11api.CKA_SENSITIVE, []note{8, 11, 9}, ` CK_TRUE if key is sensitive`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_DECRYPT", p11api.CKA_DECRYPT, []note{8, 9}, ` CK_TRUE if key supports decryption`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_SIGN", p11api.CKA_SIGN, []note{8, 9}, ` CK_TRUE if key supports signatures where the signature is an appendix to the data`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_SIGN_RECOVER", p11api.CKA_SIGN_RECOVER, []note{8, 9}, ` CK_TRUE if key supports signatures where the data can be recovered from the signature`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_UNWRAP", p11api.CKA_UNWRAP, []note{8, 9}, ` CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_EXTRACTABLE", p11api.CKA_EXTRACTABLE, []note{8, 12, 9}, ` CK_TRUE if key is extractable and can be wrapped`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_ALWAYS_SENSITIVE", p11api.CKA_ALWAYS_SENSITIVE, []note{2, 4, 6}, ` CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_NEVER_EXTRACTABLE", p11api.CKA_NEVER_EXTRACTABLE, []note{2, 4, 6}, ` CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_WRAP_WITH_TRUSTED", p11api.CKA_WRAP_WITH_TRUSTED, []note{11}, ` CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.`},
		{"", reflect.TypeOf(CK_ATTRIBUTE_PTR([]byte{})), "CKA_UNWRAP_TEMPLATE", p11api.CKA_UNWRAP_TEMPLATE, []note{}, ` For wrapping keys. The attribute template to apply to any keys unwrapped using this wrapping key. Any user supplied template is applied after this template as if the object has already been created. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.`},
		{"", reflect.TypeOf(CK_BBOOL(false)), "CKA_ALWAYS_AUTHENTICATE", p11api.CKA_ALWAYS_AUTHENTICATE, []note{}, ` If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE.`},
		{"", reflect.TypeOf(CK_Bytes([]byte{})), "CKA_PUBLIC_KEY_INFO", p11api.CKA_PUBLIC_KEY_INFO, []note{8}, ` DER-encoding of the SubjectPublicKeyInfo for the associated public key (MAY be empty; DEFAULT derived from the underlying private key data; MAY be manually set for specific key types; if set; MUST be consistent with the underlying private key data)`},
	})
}

var ckaDescByCode = make(map[uint]*CkaDesc, 0)
var ckaDescByName = make(map[string]*CkaDesc, 0)
var ckaDescByGroups = make(map[string][]*CkaDesc, 0)
var ckaDescGroupNames = make([]string, 0)

func registerCkaDesc(groupName string, ckaDescs []*CkaDesc) {
	group := make([]*CkaDesc, 0)
	for _, ckaDesc := range ckaDescs {
		ckaDesc.groupName = groupName
		ckaDescByName[ckaDesc.name] = ckaDesc
		ckaDescByCode[ckaDesc.code] = ckaDesc
		group = append(group, ckaDesc)
	}
	ckaDescByGroups[groupName] = group
	ckaDescGroupNames = append(ckaDescGroupNames, groupName)
}

func CkaDescByName(name string) *CkaDesc {
	return ckaDescByName[name]
}

func CkaDescByCode(code uint) *CkaDesc {
	return ckaDescByCode[code]
}