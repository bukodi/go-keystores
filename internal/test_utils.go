package internal

import (
	"crypto"
	"crypto/rand"
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
		t.Errorf("Sign failed: %+v", err)
	}
	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Errorf("Verify failed: %+v", err)
	} else {
		t.Logf("Sign and verify with keypair: %s (ID:%s)", kp.Label(), kp.Id())
	}
}

func EncryptDecryptTest(t *testing.T, kp keystores.KeyPair) {
	//kp.Decrypt()
	t.Logf("encrypt-decrypt test not implemented")
}

type KeyPairTestCase struct {
	Name    string
	GenOpts keystores.GenKeyPairOpts
	WantErr bool
}

func KeyPairTest(t *testing.T, ks keystores.KeyStore, alg keystores.KeyAlgorithm, keyUsage []keystores.KeyUsage) {
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
		t.Run("CreateKeyPair", func(t *testing.T) {
			if kp, err = ks.CreateKeyPair(genOpts); err != nil {
				t.Fatalf("CreateKeyPair() faield: %+v", err)
			}
		})

		defer t.Run("Destroy", func(t *testing.T) {
			if err := kp.Destroy(); err != nil {
				t.Errorf("Destroy() faield: %+v", err)
			} else {
				t.Logf("%s destroyed", kp.Label())
			}
		})

		t.Run("Check attributes", func(t *testing.T) {
			if !reflect.DeepEqual(kp.KeyUsage(), genOpts.KeyUsage) {
				t.Errorf("key usage mismatch. Expected %v, actual %v", genOpts.KeyUsage, kp.KeyUsage())
			}

			if kp.Label() != genOpts.Label {
				t.Errorf("label mismatch. Expected %v, actual %v", genOpts.Label, kp.Label())
			}
		})

		if kp.KeyUsage()[keystores.KeyUsageSign] {
			t.Run("Sign-Verify", func(t *testing.T) {
				SignVerifyTest(t, kp)
			})
		}

		if kp.KeyUsage()[keystores.KeyUsageDecrypt] {
			t.Run("Encrypt-Decrypt", func(t *testing.T) {
				EncryptDecryptTest(t, kp)
			})
		}

	})

}

func KeyPairTests(t *testing.T, ks keystores.KeyStore, tests []KeyPairTestCase) {
	type args struct {
		pubKey crypto.PublicKey
	}
	for _, tt := range tests {
		if tt.Name == "" {
			tt.Name = tt.GenOpts.Algorithm.Name
		}

		t.Run(tt.Name, func(t *testing.T) {
			kp, err := ks.CreateKeyPair(tt.GenOpts)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := kp.Destroy(); err != nil {
					t.Fatal(err)
				}
			}()

			if err != nil && kp.KeyUsage()[keystores.KeyUsageSign] {
				SignVerifyTest(t, kp)
			}

			if err != nil && kp.KeyUsage()[keystores.KeyUsageDecrypt] {
				EncryptDecryptTest(t, kp)
			}

			if (err != nil) != tt.WantErr {
				t.Errorf("KeyUsage test error = %v, WantErr %v", err, tt.WantErr)
				return
			}
		})
	}
}
