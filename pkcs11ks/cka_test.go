package pkcs11ks

import (
	"math/big"
	"testing"
	"time"
)

func TestCkaStructConverter(t *testing.T) {
	var p11KpA Pkcs11KeyPair
	p11KpA.rsaPubKeyAttrs = &RSAPublicKeyAttributes{}
	p11KpA.rsaPubKeyAttrs.CKA_PRIVATE = true
	p11KpA.rsaPubKeyAttrs.CKA_START_DATE = CK_DATE(time.Now())
	p11KpA.rsaPubKeyAttrs.CKA_MODULUS = big.NewInt(42)

	p11Attrs, err := ckaStructToP11Attrs(p11KpA.rsaPubKeyAttrs, false, true)
	if err != nil {
		t.Errorf("%+v", err)
	}
	for _, p11Attr := range p11Attrs {
		t.Logf("%s = %+v", CkaDescByCode(p11Attr.Type).name, p11Attr.Value)
	}

	var p11KpB Pkcs11KeyPair
	p11KpB.rsaPubKeyAttrs = &RSAPublicKeyAttributes{}
	err = ckaStructFromP11Attrs(p11KpB.rsaPubKeyAttrs, p11Attrs, false)
	if err != nil {
		t.Errorf("%#v", err)
	}
	t.Logf("Second struct : %+v", p11KpB.rsaPubKeyAttrs)
}
