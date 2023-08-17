package pkcs11ks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/bukodi/go-keystores"
	"testing"
)

const etoken11Lib = "/usr/lib/libeTPkcs11.so"

func TestEtoken(t *testing.T) {
	p := NewPkcs11Provider(Pkcs11Config{etoken11Lib})
	p.PINAuthenticator = func(ksDesc string, keyDesc string, isSO bool) (string, error) {
		return "Passw0rd", nil
	}

	ks, err := p.FindKeyStore("MDATestToken5110", "0255df11")
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Logf("%s: %s", ks.Id(), ks.Name())
	dumpKeys(ks, t)

	genOpts := keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgECP256,
		Label:     "ECP256 Test Key",
		KeyUsage: map[keystores.KeyUsage]bool{
			//keystores.KeyUsageAgree: true,
			keystores.KeyUsageDerive: true,
		},
		Exportable: false,
		Ephemeral:  false,
	}

	var kp keystores.KeyPair
	if kp, err = ks.CreateKeyPair(genOpts); err != nil {
		t.Fatalf("CreateKeyPair() faield: %#v", err)
	} else {
		t.Logf("Key pair created.")
	}

	defer func() {
		if err := kp.Destroy(); err != nil {
			t.Errorf("Destroy() faield: %#v", err)
		} else {
			t.Logf("%s destroyed", kp.Label())
		}
	}()

	pub := kp.Public()
	ecdsaPub, _ := pub.(*ecdsa.PublicKey)

	remotePriv, err := ecdsa.GenerateKey(ecdsaPub.Curve, rand.Reader)
	if err != nil {
		t.Errorf("remote key generation failed: %#v", err)
	}

	sharedSecret1, err := kp.ECDH(&remotePriv.PublicKey)
	if err != nil {
		t.Errorf("ecdh first phase failed: %#v", err)
	}
	remoteEcdh, err := remotePriv.ECDH()
	if err != nil {
		t.Errorf("get ecdh from ecdsa failed: %#v", err)
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		t.Errorf("get ecdh from ecdsa failed: %#v", err)
	}
	sharedSecret2, err := remoteEcdh.ECDH(ecdhPub)
	if err != nil {
		t.Errorf("ecdh verify phase failed: %#v", err)
	}

	if bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Logf("ECDH key agreement successfull with keypair: %s (ID:%s)", kp.Label(), kp.Id())
	} else {
		t.Errorf("ECDH shared secrects differs: %v, %v", sharedSecret1, sharedSecret2)
	}
}
