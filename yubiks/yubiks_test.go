package yubiks

import (
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/internal"
	"testing"
)

const testYubikeySerial = "14258488"

func TestYubiks(t *testing.T) {
	p := NewYkProvider()
	err := p.Open()
	if err != nil {
		t.Errorf("%+v", err)
	}

	ksList, err := p.KeyStores()
	if err != nil {
		t.Log(err)
	}

	var testKs keystores.KeyStore
	for i, ks := range ksList {
		t.Logf("%d. %s : %s", i, ks.Id(), ks.Name())
		if ks.Id() == testYubikeySerial {
			testKs = ks
		}
	}
	if testKs == nil {
		t.Skipf("test Yubikey with id: %s token not found", testYubikeySerial)
	}

	for _, alg := range testKs.SupportedPrivateKeyAlgorithms() {
		if alg.RSAKeyLength > 2048 {
			// Skip slow RSA operations
			continue
		}
		internal.KeyPairTest(t, testKs, alg, []keystores.KeyUsage{keystores.KeyUsageSign, keystores.KeyUsageDecrypt})
		internal.KeyPairTest(t, testKs, alg, []keystores.KeyUsage{keystores.KeyUsageSign})
		internal.KeyPairTest(t, testKs, alg, []keystores.KeyUsage{keystores.KeyUsageDecrypt})
	}

}
