package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"github.com/bukodi/go-keystores"
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

func SignVerifyTest(t *testing.T, kp keystores.KeyPair) error {
	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	}
	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		return keystores.ErrorHandler(err, kp)
	} else {
		t.Logf("Sign and verify with keypair: %s (ID:%s)", kp.Label(), kp.Id())
	}
	return nil
}

func EncryptDecryptTest(t *testing.T, kp keystores.KeyPair) error {
	// TODO
	return nil
}

type KeyPairTestCase struct {
	Name    string
	GenOpts keystores.GenKeyPairOpts
	WantErr bool
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

			if err != nil && kp.KeyUsage()&x509.KeyUsageDigitalSignature > 0 {
				err = SignVerifyTest(t, kp)
			}

			if err != nil && kp.KeyUsage()&x509.KeyUsageDataEncipherment > 0 {
				err = EncryptDecryptTest(t, kp)
			}

			if (err != nil) != tt.WantErr {
				t.Errorf("KeyUsage test error = %v, WantErr %v", err, tt.WantErr)
				return
			}
		})
	}
}
