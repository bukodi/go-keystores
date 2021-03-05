package keystores

import (
	"github.com/miekg/pkcs11"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

var softhsm2Lib = "/usr/local/lib/softhsm/libsofthsm2.so"

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

func TestSoftHSM(t *testing.T) {
	p := pkcs11.New(softhsm2Lib)
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
	initSoftHSM2TestEnv(t)
	ksList, err := ListPkcs11KeyStores(softhsm2Lib)
	if err != nil {
		t.Fatal(err)
	}
	for i, ks := range ksList {
		t.Logf("%d. %s, %s", i, ks.tokenInfo.Label, ks.tokenInfo.SerialNumber)
	}

}
