package yubiks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"github.com/go-piv/piv-go/piv"
	"math/big"
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
		t.Skipf("Yubikey not found")
	}

	if serial, err := yk.Serial(); err != nil {
		t.Fatalf("getting serial number: %v", err)
	} else {
		t.Logf("Yubikey serial: %v", serial)
	}

	// Change Master password
	// Set all values to a new value.
	/*var newKey [24]byte
	for i:= 0; i < len(newKey); i ++ {
		newKey[i] = 7
	}

	if err := yk.SetManagementKey(newKey, piv.DefaultManagementKey); err != nil {
		t.Fatalf("SetManagementKey failed: %v", err)
	}*/
	if md, err := yk.Metadata(piv.DefaultPIN); err != nil {
		t.Fatalf("getting serial number: %v", err)
	} else {
		t.Logf("Metadata: %#v", md)
	}

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyCached,
	}
	pubKey, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
	if err != nil {
		t.Fatal(err)
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	privKey, err := yk.PrivateKey(piv.SlotAuthentication, pubKey, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Priv key: %#v", privKey)

	// Use private key to sign or decrypt.
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))
	s, ok := privKey.(crypto.Signer)
	if !ok {
		t.Fatalf("expected private key to implement crypto.Signer")
	}
	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	} else {
		t.Logf(`Signature of "hello": %+v`, out)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		t.Fatalf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		t.Errorf("signature didn't match")
	} else {
		t.Logf("Signature verified.")
	}

	// Get the YubiKey's attestation certificate, which is signed by Yubico.
	yubiKeyAttestationCert, err := yk.AttestationCertificate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Attestation cert:")
	dumpCert(yubiKeyAttestationCert, t)
	//os.WriteFile("/tmp/yubiKeyAttestationCert.der", yubiKeyAttestationCert.Raw, 0666)

	slotAttestationCertificate, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Slot attestation cert: ")
	dumpCert(slotAttestationCertificate, t)
	//os.WriteFile("/tmp/slotKeyAttestationCert.der", slotAttestationCertificate.Raw, 0666)

}

func dumpCert(cert *x509.Certificate, t *testing.T) {
	t.Logf("Subject name: %s", cert.Subject.String())
	t.Logf("Issuer name: %s", cert.Issuer.String())
	t.Logf("Serial: %s", cert.SerialNumber.String())
}
