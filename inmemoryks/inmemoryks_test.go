package inmemoryks

import (
	"bytes"
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

func TestJKSExport(t *testing.T) {
	ks := CreateInMemoryKeyStore()

	if kp, err := ks.CreateKeyPair(keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgRSA2048}); err != nil {
		t.Fatal(err)
	} else {
		kp.SetLabel("rsa1")
	}
	if kp, err := ks.CreateKeyPair(keystores.GenKeyPairOpts{Algorithm: keystores.KeyAlgECP256}); err != nil {
		t.Fatal(err)
	} else {
		kp.SetLabel("ecp256")
	}

	var b bytes.Buffer
	err := ks.SaveAsJKS(&b, []byte("Passw0rd"))
	if err != nil {
		t.Fatal(err)
	}

	var b2 bytes.Buffer
	b2.Write(b.Bytes())

	ks2 := CreateInMemoryKeyStore()
	err = ks2.LoadFromJKS(&b2, []byte("Passw0rd"))
	if err != nil {
		t.Fatal(err)
	}
	kps, _ := ks2.KeyPairs()
	for _, kp := range kps {
		t.Logf("%v", kp)
	}
}
