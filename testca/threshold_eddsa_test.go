package testca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/coinbase/kryptology/pkg/ted25519/ted25519"
	"os"
	"testing"
)

func TestSimpleEDDSA(t *testing.T) {
	msg := "Hello 123"

	argCount := len(os.Args[1:])
	if argCount > 0 {
		msg = os.Args[1]
	}

	publ, priv, _ := ed25519.GenerateKey(nil)

	m := []byte(msg)
	digest := sha256.Sum256(m)

	sig := ed25519.Sign(priv, digest[:])

	fmt.Printf("=== Message ===\n")
	fmt.Printf("Msg=%s\nHash=%x\n", msg, digest)
	fmt.Printf("\n=== Private key ===\n")
	fmt.Printf("Public key=%x\n\n", publ)
	fmt.Printf("Private key=%x\n\n", priv[0:32])
	fmt.Printf("Signature: (%x,%x)\n\n", sig[0:32], sig[32:64])

	rtn := ed25519.Verify(publ, digest[:], sig)

	if rtn {
		fmt.Printf("Signature verifies")
	} else {
		fmt.Printf("Signature does not verify")
	}
}

func TestThresholdEDDSA(t *testing.T) {
	msg := "Hello 123"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		msg = os.Args[1]
	}
	message := []byte(msg)

	config := ted25519.ShareConfiguration{T: 2, N: 4}
	pub, secretShares, _, _ := ted25519.GenerateSharedKey(&config)

	// Each party generates a nonce and we combine them together into an aggregate one
	noncePub1, nonceShares1, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[0], pub, message)
	noncePub2, nonceShares2, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[1], pub, message)
	noncePub3, nonceShares3, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[2], pub, message)
	noncePub4, nonceShares4, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[3], pub, message)

	nonceShares := []*ted25519.NonceShare{
		nonceShares1[0].Add(nonceShares2[0]).Add(nonceShares3[0]).Add(nonceShares4[0]),
		nonceShares1[1].Add(nonceShares2[1]).Add(nonceShares3[1]).Add(nonceShares4[1]),
		nonceShares1[2].Add(nonceShares2[2]).Add(nonceShares3[2]).Add(nonceShares4[2]),
		nonceShares1[3].Add(nonceShares2[3]).Add(nonceShares3[3]).Add(nonceShares4[3]),
	}

	noncePub := ted25519.GeAdd(ted25519.GeAdd(ted25519.GeAdd(noncePub1, noncePub2), noncePub3), noncePub4)

	sig1 := ted25519.TSign(message, secretShares[0], pub, nonceShares[0], noncePub)
	sig2 := ted25519.TSign(message, secretShares[1], pub, nonceShares[1], noncePub)
	sig3 := ted25519.TSign(message, secretShares[2], pub, nonceShares[2], noncePub)
	sig4 := ted25519.TSign(message, secretShares[3], pub, nonceShares[3], noncePub)

	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Public key: %x\n", pub.Bytes())
	epub := convertPubKey(pub)

	fmt.Printf("\nThreshold Sig1: %x\n", sig1.Bytes())
	fmt.Printf("Threshold Sig2: %x\n", sig2.Bytes())
	fmt.Printf("Threshold Sig3: %x\n", sig3.Bytes())
	fmt.Printf("Threshold Sig4: %x\n\n", sig4.Bytes())

	sig13, _ := ted25519.Aggregate([]*ted25519.PartialSignature{sig1, sig3}, &config)
	fmt.Printf("Rebuild signature with share 1 and 3: %x\n", sig13)

	sig23, _ := ted25519.Aggregate([]*ted25519.PartialSignature{sig2, sig3}, &config)
	fmt.Printf("Rebuild signature with share 2 and 3: %x\n", sig23)

	sig12, _ := ted25519.Aggregate([]*ted25519.PartialSignature{sig1, sig2}, &config)
	fmt.Printf("Rebuild signature with share 2 and 3: %x\n", sig12)

	sig24, _ := ted25519.Aggregate([]*ted25519.PartialSignature{sig2, sig4}, &config)
	fmt.Printf("Rebuild signature with share 2 and 3: %x\n", sig24)

	if bytes.Equal(sig13, sig23) && bytes.Equal(sig13, sig12) && bytes.Equal(sig13, sig24) {
		fmt.Printf("\nSignatures 13 and 23 are equal")
	} else {
		fmt.Printf("\nSignatures 13 and 23 are not equal")
	}

	ok, err := ted25519.Verify(pub, message, sig23)
	if ok {
		fmt.Printf("\nSignature verified by ted25519.Verify")
	} else {
		fmt.Printf("\nSignature unverified by ted25519.Verify: %v", err)
	}

	ok = ed25519.Verify(epub, message, sig23)
	if ok {
		fmt.Printf("\nSignature verified by ed25519.Verify")
	} else {
		fmt.Printf("\nSignature unverified by ed25519.Verify")
	}
	fmt.Printf("\n")
}

func convertPubKey(tpub ted25519.PublicKey) ed25519.PublicKey {
	var pub ed25519.PublicKey
	pub = tpub.Bytes()
	return pub
}
