package tpm2ks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"golang.org/x/crypto/cryptobyte"
	"math/big"
	"testing"

	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func ecdhSignatureToASN1(r *big.Int, s *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteAsn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	bytes, err := b.Bytes()
	if err != nil {
		return nil
	} else {
		return bytes
	}
}
func ecdhSignatureToASN1Wrong(r *big.Int, s *big.Int) []byte {
	type ECDSASignature struct {
		R, S *big.Int
	}
	// unmarshal the R and S components of the ASN.1-encoded signature into our
	// signature data structure
	sig := &ECDSASignature{
		R: r,
		S: s,
	}
	bytes, err := asn1.Marshal(sig)
	if err != nil {
		return nil
	} else {
		return bytes
	}
}

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

func TestECDSASignVerifyANS1(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plain := "Hello world!"
	digest := sha256.Sum256([]byte(plain))

	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	valid := ecdsa.Verify(&ecKey.PublicKey, digest[:], r, s)
	if !valid {
		t.Fatalf("R+S format signature validation failed")
	}

	//asn1Sig := ecdhSignatureToASN1(r, s)
	asn1Sig := ecdhSignatureToASN1(r, s)

	// validate the signature!
	valid = ecdsa.VerifyASN1(&ecKey.PublicKey, digest[:], asn1Sig)
	if !valid {
		t.Fatalf("ASN1 format signature validation failed")
	}
}
