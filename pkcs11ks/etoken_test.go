package pkcs11ks

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
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

func TestEtokenRsaImport(t *testing.T) {
	p := NewPkcs11Provider(Pkcs11Config{etoken11Lib})
	p.PINAuthenticator = func(ksDesc string, keyDesc string, isSO bool) (string, error) {
		return "Passw0rd", nil
	}

	ks, err := p.FindKeyStore("MDATestToken5110", "0255df11")
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Logf("%s: %s", ks.Id(), ks.Name())

	goRsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	dumpKeys(ks, t)
	kp, err := ks.ImportKeyPair(goRsaKey, keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgRSA2048,
		Label:     "importedRSAKey",
		KeyUsage: map[keystores.KeyUsage]bool{
			keystores.KeyUsageSign: true,
		},
		Exportable: false,
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer func() {
		err = kp.Destroy()
		if err != nil {
			dumpKeys(ks, t)
			t.Fatalf("%+v", err)
		}
	}()

	dumpKeys(ks, t)
	var kpTest *Pkcs11KeyPair
	kpSlice, err := ks.KeyPairs(true)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	for _, kp := range kpSlice {
		if kp.Label() == "importedRSAKey" {
			kpTest = kp.(*Pkcs11KeyPair)
		}
	}
	if kpTest == nil {
		t.Fatal(errors.New("importedRSAKey not found"))
	} else {
		t.Logf("importedRSAKey found: %#v", kpTest)
	}

	digest := sha256.Sum256([]byte("Hello world!"))
	signature, err := kp.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	err = rsa.VerifyPSS(kp.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("%+v", err)
	} else {
		t.Logf("RSA PSS signature verified")
	}

	signature, err = kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	err = rsa.VerifyPKCS1v15(kp.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature)
	if err != nil {
		t.Fatalf("%+v", err)
	} else {
		t.Logf("RSA PKCS1v15 signature verified")
	}

}

func TestEtokenECCImport(t *testing.T) {
	p := NewPkcs11Provider(Pkcs11Config{etoken11Lib})
	p.PINAuthenticator = func(ksDesc string, keyDesc string, isSO bool) (string, error) {
		return "Passw0rd", nil
	}

	ks, err := p.FindKeyStore("MDATestToken5110", "0255df11")
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Logf("%s: %s", ks.Id(), ks.Name())

	goECCKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	dumpKeys(ks, t)
	kp, err := ks.ImportKeyPair(goECCKey, keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgECP256,
		Label:     "importedECCKey",
		KeyUsage: map[keystores.KeyUsage]bool{
			keystores.KeyUsageSign: true,
		},
		Exportable: false,
	})
	if err != nil {
		t.Fatalf("%#v", err)
	}
	defer func() {
		err = kp.Destroy()
		if err != nil {
			dumpKeys(ks, t)
			t.Fatalf("%+v", err)
		}
	}()

	dumpKeys(ks, t)
	var kpTest *Pkcs11KeyPair
	kpSlice, err := ks.KeyPairs(true)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	for _, kp := range kpSlice {
		if kp.Label() == "importedECCKey" {
			kpTest = kp.(*Pkcs11KeyPair)
		}
	}
	if kpTest == nil {
		t.Fatal(errors.New("importedECCKey not found"))
	} else {
		t.Logf("importedECCKey found: %#v", kpTest)
	}

	digest := sha256.Sum256([]byte("Hello world!"))
	signature, err := kp.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	err = rsa.VerifyPSS(kp.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("%+v", err)
	} else {
		t.Logf("RSA PSS signature verified")
	}

	signature, err = kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	err = rsa.VerifyPKCS1v15(kp.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature)
	if err != nil {
		t.Fatalf("%+v", err)
	} else {
		t.Logf("RSA PKCS1v15 signature verified")
	}

}
