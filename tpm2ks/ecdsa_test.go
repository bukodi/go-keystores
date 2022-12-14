package tpm2ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestECDSASignVerify(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plain := "Hello world!"
	digest := sha256.Sum256([]byte(plain))

	signature, err := ecKey.Sign(rand.Reader, digest[:], crypto.SHA256)

	type ECDSASignature struct {
		R, S *big.Int
	}
	// unmarshal the R and S components of the ASN.1-encoded signature into our
	// signature data structure
	sig := &ECDSASignature{}
	_, err = asn1.Unmarshal(signature, sig)
	if err != nil {
		t.Fatal(err)
	}

	// validate the signature!
	valid := ecdsa.Verify(
		&ecKey.PublicKey,
		digest[:],
		sig.R,
		sig.S,
	)
	if !valid {
		t.Fatalf("Signature validation failed")
	}

}
