package yubiks

import (
	"github.com/go-piv/piv-go/piv"
	"strings"
	"testing"
)

func TestYubikey(t *testing.T) {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		t.Fatal(err) // ...
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				t.Fatal(err) // ...
			}
			break
		}
	}
	if yk == nil {
		t.Fatal("Yubikey not found")
	}

	if serial, err := yk.Serial(); err != nil {
		t.Fatalf("getting serial number: %v", err)
	} else {
		t.Logf("Yubikey serial: %v", serial)
	}

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
	if err != nil {
		t.Fatal(err)
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	priv, err := yk.PrivateKey(piv.SlotAuthentication, pub, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Priv key: %#v", priv)

	// Use private key to sign or decrypt.

	// Get the YubiKey's attestation certificate, which is signed by Yubico.
	yubiKeyAttestationCert, err := yk.AttestationCertificate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Attestation cert: %#v", yubiKeyAttestationCert)

	slotAttestationCertificate, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Slot attestation cert: %#v", slotAttestationCertificate)

}
