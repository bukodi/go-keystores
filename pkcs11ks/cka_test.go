package pkcs11ks

import (
	"testing"
	"time"
)

func TestCkaStructConverter(t *testing.T) {
	var p11KpA Pkcs11KeyPair
	p11KpA.PublicKeyAttributes.CKA_PRIVATE = true
	p11KpA.PublicKeyAttributes.CKA_START_DATE = CK_DATE(time.Now())

	p11Attrs, err := ckaStructToP11Attrs(&p11KpA.PublicKeyAttributes)
	if err != nil {
		t.Error(err)
	}
	for _, p11Attr := range p11Attrs {
		t.Logf("%s = %+v", CkaDescByCode(p11Attr.Type).name, p11Attr.Value)
	}

	var p11KpB Pkcs11KeyPair
	err = ckaStructFromP11Attrs(&(p11KpB.PrivateKeyAttributes), p11Attrs)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Second struct : %+v", p11KpB.PublicKeyAttributes)
}