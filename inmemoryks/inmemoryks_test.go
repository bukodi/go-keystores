package inmemoryks

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/internal"
	"regexp"
	"testing"
)

func TestSupportedAlgs(t *testing.T) {
	ks := CreateInMemoryKeyStore()
	algs := ks.SupportedPrivateKeyAlgorithms()
	t.Logf("%+v", algs)
	kp, err := ks.CreateKeyPair(keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgRSA2048})
	if err != nil {
		t.Fatal(err)
	}
	//var hashFunc crypto.Hash

	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Digest : %+v", digest)
	t.Logf("Signature: %+v", signature)
	t.Logf("%+v", kp)

	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("%+v", err)
	} else {
		t.Logf("Signature is valid")
	}
}

func TestKeys(t *testing.T) {
	ks := CreateInMemoryKeyStore()

	tests := []internal.KeyPairTestCase{
		{GenOpts: keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgRSA2048}},
		{GenOpts: keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgECP256}},
		{GenOpts: keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgEd25519}},
	}

	internal.KeyPairTests(t, ks, tests)
}

func TestParseFilename(t *testing.T) {
	re := regexp.MustCompile(`^([0-9a-z]*)-(.*)\.priv$`)
	match := re.FindStringSubmatch("789a7c4-cica.priv")
	t.Logf("%s-%s.priv", match[1], match[2])

}
