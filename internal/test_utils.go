package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/bukodi/go-keystores"
	"reflect"
	"testing"
)

func CreateKeyPairForTests(t *testing.T, ks keystores.KeyStore, opts keystores.GenKeyPairOpts) (keystores.KeyPair, func(kp keystores.KeyPair)) {
	kp, err := ks.CreateKeyPair(opts)
	if err != nil {
		t.Fatal(err)
	}
	return kp, func(kp keystores.KeyPair) {
		if err := kp.Destroy(); err != nil {
			t.Fatal(err)
		}
	}
}

func SignVerifyTest(t *testing.T, kp keystores.KeyPair) {
	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Errorf("Sign failed: %#v", err)
	}
	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Errorf("Verify failed: %#v", err)
	} else {
		t.Logf("Sign and verify with keypair: %s (ID:%s)", kp.Label(), kp.Id())
	}
}

func SignVerifyRSAPSSTest(t *testing.T, kp keystores.KeyPair) {
	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Errorf("Sign failed: %#v", err)
	}
	err = rsa.VerifyPSS(kp.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256})
	// TODO: use this also
	//err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Errorf("Verify failed: %#v", err)
	} else {
		t.Logf("RSA PSS sign and verify with keypair: %s (ID:%s)", kp.Label(), kp.Id())
	}
}

func EncryptDecryptTest(t *testing.T, kp keystores.KeyPair) {
	//kp.Decrypt()
	t.Skipf("encrypt-decrypt test not implemented")
}

type KeyPairTestCase struct {
	Name    string
	GenOpts keystores.GenKeyPairOpts
	WantErr bool
}

func KeyPairTest(t *testing.T, ks keystores.KeyStore, alg keystores.KeyAlgorithm, keyUsage []keystores.KeyUsage) {
	t.Helper()
	t.Run(fmt.Sprintf("%s %v", alg.Name, keyUsage), func(t *testing.T) {
		genOpts := keystores.GenKeyPairOpts{
			Algorithm:  alg,
			Label:      fmt.Sprintf("TestKP-%s", alg.Name),
			KeyUsage:   make(map[keystores.KeyUsage]bool),
			Exportable: false,
			Ephemeral:  false,
		}
		for _, ku := range keyUsage {
			genOpts.KeyUsage[ku] = true
		}
		var err error
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

		if !reflect.DeepEqual(kp.Algorithm(), genOpts.Algorithm) {
			t.Errorf("Algorithm mismatch. Expected %v, actual %v", genOpts.Algorithm, kp.Algorithm())
		} else {
			t.Logf("Key Algorithm checked")
		}

		if !reflect.DeepEqual(kp.KeyUsage(), genOpts.KeyUsage) {
			t.Errorf("key usage mismatch. Expected %v, actual %v", genOpts.KeyUsage, kp.KeyUsage())
		} else {
			t.Logf("KeyUsage checked")
		}

		if kp.Label() != genOpts.Label {
			t.Errorf("label mismatch. Expected %v, actual %v", genOpts.Label, kp.Label())
		} else {
			t.Logf("Label checked")
		}

		if kp.KeyUsage()[keystores.KeyUsageSign] {
			SignVerifyTest(t, kp)

			if kp.Algorithm().RSAKeyLength > 0 {
				SignVerifyRSAPSSTest(t, kp)
			}
		}

		if kp.KeyUsage()[keystores.KeyUsageDecrypt] {
			EncryptDecryptTest(t, kp)
		}

	})

}
