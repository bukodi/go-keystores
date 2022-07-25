package pkcs11ks

import (
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"github.com/rainycape/dl"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

//var softhsm2Lib = "/usr/local/lib/softhsm/libsofthsm2.so"

var softhsm2Lib = "/usr/lib/softhsm/libsofthsm2.so"

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

func TestDump(t *testing.T) {
	var x CommonKeyAttributes

	ts := reflect.TypeOf(x)
	t.Logf(ts.Name())
	if ts.Kind() != reflect.Struct {
		t.Logf(ts.Kind().String())
		return
	}

	for i := 0; i < ts.NumField(); i++ {
		f := ts.Field(i)

		t.Logf("%s %s", f.Name, f.Type.String())
	}

}

func TestDloadLib(t *testing.T) {
	lib, err := dl.Open(softhsm2Lib, 0)
	if err != nil {
		log.Fatalln(err)
	}
	defer lib.Close()
}

func TestSoftHSM(t *testing.T) {
	p := p11api.New(softhsm2Lib)
	err := p.Initialize()
	if err != nil {
		t.Fatal(err)
	}

	defer p.Destroy()
	defer func() {
		err = p.Finalize()
		if err != nil {
			t.Error(err)
		}
	}()
}

func TestListPksc11KeyStores(t *testing.T) {
	initSoftHSM2TestEnv(t)
	p := NewPkcs11Provider(Pkcs11Config{softhsm2Lib})
	err := keystores.EnsureOpen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer keystores.MustClosed(p)

	ksList, errs := p.KeyStores()
	if errs != nil {
		for _, err = range errs {
			t.Log(err)
		}
		t.Fatal()
	}

	for i, ks := range ksList {
		t.Logf("%d. %s : %s", i, ks.Id(), ks.Name())
	}

}

func TestRsaGenSignVerify(t *testing.T) {
	initSoftHSM2TestEnv(t)
	p := NewPkcs11Provider(Pkcs11Config{softhsm2Lib})
	err := keystores.EnsureOpen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer keystores.MustClosed(p)

	ks, err := p.FindKeyStore("TestTokenA", "")
	if err != nil {
		t.Fatal(err)
	}

	err = keystores.EnsureOpen(ks)
	if err != nil {
		t.Fatal(err)
	}
	defer keystores.MustClosed(ks)

	dumpKeys(ks, t)
	kp, err := ks.CreateKeyPair(keystores.GenKeyPairOpts{
		Algorithm:  keystores.KeyAlgRSA2048,
		Label:      "testKey",
		KeyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		Exportable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = kp.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}()

	dumpKeys(ks, t)

}

func dumpKeys(ks *Pkcs11KeyStore, t *testing.T) {
	kps, errs := ks.KeyPairs()
	if errs != nil {
		t.Fatal(errs)
	}
	if len(kps) == 0 {
		t.Logf("No key pairs.")
	} else {
		for i, kp := range kps {
			t.Logf("%d.: Label: %s, Id: %s", i, kp.Label(), kp.Id())
		}
	}
}
