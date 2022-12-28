package internal

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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

func rsaEncryptDecryptPKCSv15(kp keystores.KeyPair, plainText []byte) error {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, kp.Public().(*rsa.PublicKey), plainText)
	if err != nil {
		return err
	}
	plainText2, err := kp.Decrypt(rand.Reader, cipherText, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(plainText, plainText2) {
		return fmt.Errorf("decrypt failed. Expected %v, actual: %v", plainText, plainText2)
	}
	return nil
}

func rsaEncryptDecryptOAEP(kp keystores.KeyPair, plainText []byte) error {
	// The SoftHSM 2.6.1 only supports the SHA1 hash

	label := []byte("testLabel")
	cipherText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, kp.Public().(*rsa.PublicKey), plainText, label)
	if err != nil {
		return err
	}
	plainText2, err := kp.Decrypt(rand.Reader, cipherText, &rsa.OAEPOptions{
		Hash:  crypto.SHA1,
		Label: label,
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(plainText, plainText2) {
		return fmt.Errorf("decrypt failed. Expected %v, actual: %v", plainText, plainText2)
	}
	return nil
}

func EncryptDecryptTest(t *testing.T, kp keystores.KeyPair) {
	plainText := []byte("Hello world!")
	pub := kp.Public()
	if _, ok := pub.(*rsa.PublicKey); ok {
		if err := rsaEncryptDecryptPKCSv15(kp, plainText); err != nil {
			t.Errorf("PKCS#1 1.5 encrypt - decrypt failed: %#v", err)
		} else {
			t.Logf("PKCS#1 1.5 encrypt - decrypt successfull with keypair: %s (ID:%s)", kp.Label(), kp.Id())
		}
		if err := rsaEncryptDecryptOAEP(kp, plainText); err != nil {
			t.Errorf("RSA OAEP encrypt - decrypt failed: %s (%#v)", err.Error(), err)
		} else {
			t.Logf("RSA OAEP encrypt - decrypt successfull with keypair: %s (ID:%s)", kp.Label(), kp.Id())
		}
	} else {
		t.Skipf("encrypt-decrypt for %T key type not implemented", pub)
	}
}

type KeyPairTestCase struct {
	Name    string
	GenOpts keystores.GenKeyPairOpts
	WantErr bool
}

func KeyPairTest(t *testing.T, ks keystores.KeyStore, alg keystores.KeyAlgorithm, keyUsage []keystores.KeyUsage) {
	t.Helper()
	t.Run(fmt.Sprintf("%s %v", alg.Name, keyUsage), func(t *testing.T) {
		t.Helper()
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
