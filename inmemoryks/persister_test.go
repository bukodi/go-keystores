package inmemoryks

import (
	"github.com/bukodi/go-keystores"
	"os"
	"path/filepath"
	"testing"
)

func TestPkcs8DirPersister(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pkcs8Dir")
	os.MkdirAll(dir, 0700)

	t.Logf("Persister dir: %s", dir)
	imks, err := CreatePkcs8Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := imks.Open(); err != nil {
		t.Fatal(err)
	}
	kp, err := imks.CreateKeyPair(keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgRSA2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Generated key ID: %s", kp.Id())
	if err := imks.Close(); err != nil {
		t.Fatal(err)
	}
}
