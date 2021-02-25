package keystores

import (
	"github.com/miekg/pkcs11"
	"testing"
)

func TestSoftHSM(t *testing.T) {
	p := pkcs11.New("/usr/local/lib/softhsm/libsofthsm2.so")
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer func() {
		err = p.Finalize()
		if err != nil {
			t.Error(err)
		}
	}()
}

func TestPksc11KeyStore(t *testing.T) {
	ks, err := OpenPkcs11KeyStore("/usr/local/lib/softhsm/libsofthsm2.so", "", "")
	if err != nil {
		t.Fatal(err)
	}
	algs := ks.SupportedPrivateKeyAlgorithms()
	t.Logf("%+v", algs)
}

func TestListPksc11KeyStores(t *testing.T) {
	ksList, err := ListPkcs11KeyStores("/usr/local/lib/softhsm/libsofthsm2.so")
	if err != nil {
		t.Fatal(err)
	}
	for i, ks := range ksList {
		t.Logf("%d. %s, %s", i, ks.tokenInfo.Label, ks.tokenInfo.SerialNumber)
	}

}
