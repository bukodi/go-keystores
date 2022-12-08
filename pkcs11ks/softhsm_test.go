package pkcs11ks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/internal"
	p11api "github.com/miekg/pkcs11"
	"github.com/rainycape/dl"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

var softhsm2Lib = "/usr/local/lib/softhsm/libsofthsm2.so"

//var softhsm2Lib = "/usr/lib/softhsm/libsofthsm2.so"

//var softhsm2Lib = "/opt/SoftHSMv2/lib/softhsm/libsofthsm2.so"

//var softhsm2Lib = "libsofthsm2.so"

func initSoftHSM2TestEnv(t *testing.T) {
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib != "" {
		softhsm2Lib = lib
	}

	tmpDir := t.TempDir()
	confContent := `
log.level = INFO
objectstore.backend = file
directories.tokendir = ` + tmpDir + `
slots.removable = false`

	confPath := path.Join(tmpDir, "softhsm2.conf")
	err := os.WriteFile(confPath, []byte(confContent), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Setenv("SOFTHSM2_CONF", confPath)
	if err != nil {
		t.Fatal(err)
	}

	wd, _ := os.Getwd()
	wd = filepath.Dir(wd)
	err = copyDir(filepath.Join(wd, "test_softhsm2"), tmpDir)

}

func copyDir(source, destination string) error {
	var err error = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		var relPath string = strings.Replace(path, source, "", 1)
		if relPath == "" {
			return nil
		}
		if info.IsDir() {
			return os.Mkdir(filepath.Join(destination, relPath), 0755)
		} else {
			var data, err1 = ioutil.ReadFile(filepath.Join(source, relPath))
			if err1 != nil {
				return err1
			}
			return ioutil.WriteFile(filepath.Join(destination, relPath), data, 0777)
		}
	})
	return err
}

func TestDloadLib(t *testing.T) {
	lib, err := dl.Open(softhsm2Lib, 0)
	if err != nil {
		log.Fatalln(err)
	}
	defer lib.Close()
}

func TestSoftHSMWithLowLevelAPI(t *testing.T) {
	p := p11api.New(softhsm2Lib)
	err := p.Initialize()
	if err != nil {
		t.Fatalf("%+v", err)
	}

	info, err := p.GetInfo()
	if err != nil {
		t.Errorf("%+v", err)
	} else {
		t.Logf("Driver info: %+v", info)
	}

	defer p.Destroy()
	defer func() {
		err = p.Finalize()
		if err != nil {
			t.Errorf("%+v", err)
		}
	}()
}

func TestSoftHSM2KeyStore(t *testing.T) {
	initSoftHSM2TestEnv(t)
	p := NewPkcs11Provider(Pkcs11Config{softhsm2Lib})
	err := keystores.EnsureOpen(p)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	defer keystores.MustClosed(p)

	ksList, errs := p.KeyStores()
	if errs != nil {
		for _, err = range errs {
			t.Log(err)
		}
		t.Fatal()
	}

	var ksTestTokenA *Pkcs11KeyStore
	for i, ks := range ksList {
		t.Logf("%d. %s : %s", i, ks.Id(), ks.Name())
		if "TestTokenA" == ks.Name() {
			ksTestTokenA, _ = ks.(*Pkcs11KeyStore)
		}
	}
	if ksTestTokenA == nil {
		t.Fatalf("TestTokenA not found")
	}

	for _, alg := range ksTestTokenA.SupportedPrivateKeyAlgorithms() {
		if alg.RSAKeyLength > 1024 {
			// Skip slow RSA operations
			continue
		}
		internal.KeyPairTest(t, ksTestTokenA, alg, []keystores.KeyUsage{keystores.KeyUsageSign, keystores.KeyUsageDecrypt})
		internal.KeyPairTest(t, ksTestTokenA, alg, []keystores.KeyUsage{keystores.KeyUsageSign})
		internal.KeyPairTest(t, ksTestTokenA, alg, []keystores.KeyUsage{keystores.KeyUsageDecrypt})
	}
}

func TestRsaGenSignVerify(t *testing.T) {
	initSoftHSM2TestEnv(t)
	p := NewPkcs11Provider(Pkcs11Config{softhsm2Lib})
	err := keystores.EnsureOpen(p)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer keystores.MustClosed(p)

	ks, err := p.FindKeyStore("TestTokenA", "")
	if err != nil {
		t.Fatalf("%+v", err)
	}

	err = keystores.EnsureOpen(ks)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer keystores.MustClosed(ks)

	dumpKeys(ks, t)
	kp, err := ks.CreateKeyPair(keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgRSA2048,
		Label:     "testKey",
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
		if kp.Label() == "testKey" {
			kpTest = kp.(*Pkcs11KeyPair)
		}
	}
	if kpTest == nil {
		t.Fatal(errors.New("testKp not found"))
	} else {
		t.Logf("Test key found: %#v", kpTest)
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

func dumpKeys(ks *Pkcs11KeyStore, t *testing.T) {
	kps, err := ks.KeyPairs(true)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	if len(kps) == 0 {
		t.Logf("No key pairs.")
	} else {
		t.Logf("--- %d key pairs --- ", len(kps))
		for _, kp := range kps {
			p11Kp := kp.(*Pkcs11KeyPair)
			t.Logf(" Class: %d, Label: %s, CKA_ID: %v, Id: %s", p11Kp.commonPrivateKeyAttributes().CKA_CLASS, kp.Label(), p11Kp.commonPrivateKeyAttributes().CKA_ID, kp.Id())
		}
	}
}
