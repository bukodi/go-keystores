package tpm2ks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/simulator"
	"io"
	"log"
	"testing"
)

func TestSignVerify(t *testing.T) {
	f, _ := openTpm()
	ek, err := client.EndorsementKeyECC(f)
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}

	srk, err := client.StorageRootKeyECC(f)
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}
	_ = srk

	//pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	importBlob, err := server.CreateSigningKeyImportBlob(ek.PublicKey(), pk, nil)
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}

	signKey, err := ek.ImportSigningKey(importBlob)
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}

	signer, err := signKey.GetSigner()
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}
	digest := sha256.Sum256([]byte("Hello"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("%s %#v", err.Error(), err)
	}

	//if ecdsa.VerifyASN1(&pk.PublicKey, digest[:], signature) {
	if err := rsa.VerifyPKCS1v15(&pk.PublicKey, crypto.SHA256, digest[:], signature); err == nil {
		t.Logf("Signature verified")
	} else {
		t.Fatalf("Signature verification failed")
	}
}

func TestAttest(t *testing.T) {
	// On verifier, make the nonce.
	nonce := make([]byte, 8)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("failed to create nonce: %v", err)
	}

	// On client machine, generate the TPM quote.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	ak, err := client.AttestationKeyECC(simulator)
	if err != nil {
		log.Fatalf("failed to create attestation key: %v", err)
	}
	defer ak.Close()

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	// TODO: establish trust in the AK (typically via an AK certificate signed
	// by the manufacturer).
	// On verifier, verify the Attestation message. This:
	//  - checks the quote(s) against a stored public key/AK
	// certificate's public part and the expected nonce.
	//  - replays the event log against the quoted PCRs
	//  - extracts events into a MachineState message.
	// TODO: decide which hash algorithm to use in the quotes. SHA1 is
	// typically undesirable but is the only event log option on some distros.
	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{ak.PublicKey()}})
	if err != nil {
		// TODO: handle parsing or replay error.
		log.Fatalf("failed to read PCRs: %v", err)
	}
	fmt.Println(attestation)
	// TODO: use events output of ParseMachineState.
}
