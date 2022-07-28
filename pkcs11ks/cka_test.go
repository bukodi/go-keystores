package pkcs11ks

import (
	"testing"
)

func TestCkType(t *testing.T) {

	var b1, b2 CK_BBOOL
	b1 = true
	buff, err := b1.write()
	if err != nil {
		t.Fatal(err)
	}

	b3, err := b2.read(buff)
	b2 = b3

}

func TestCkaStructConverter(t *testing.T) {
	var p11Kp Pkcs11KeyPair
	p11Kp.PublicKeyAttributes.CKA_PRIVATE = true

	p11Attrs, err := ckaStructToP11Attrs(&p11Kp.PublicKeyAttributes)
	if err != nil {
		t.Error(err)
	}
	for _, p11Attr := range p11Attrs {
		t.Logf("%s = %+v", CkaDescByCode(p11Attr.Type).name, p11Attr.Value)
	}
}
