package keystores

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestSupportedAlgs(t *testing.T) {
	ks := CreateInMemoryKeyStore()
	algs := ks.SupportedPrivateKeyAlgorithms()
	t.Logf("%+v", algs)
	kp, err := ks.CreateKeyPair(KeyAlgRSA2048, nil)
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

func TestRSASignVerify(t *testing.T) {
	testSignVerify(t, KeyAlgRSA2048)
}

func TestECDSASignVerify(t *testing.T) {
	testSignVerify(t, KeyAlgECP256)
}

func TestEd25519SignVerify(t *testing.T) {
	testSignVerify(t, KeyAlgEd25519)
}

func testSignVerify(t *testing.T, algorithm KeyAlgorithm) {
	ks := CreateInMemoryKeyStore()
	kp, err := ks.CreateKeyPair(algorithm, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Digest : %+v", digest)
	t.Logf("Signature: %+v", signature)
	t.Logf("Sign as b64: %s", base64.StdEncoding.EncodeToString(signature))

	t.Logf("%+v", kp)

	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("Signature is valid")
	}
}
