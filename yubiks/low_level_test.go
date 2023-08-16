package yubiks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/go-piv/piv-go/piv"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
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

	// List slots
	slots := make([]piv.Slot, 0)
	slots = append(slots, piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuthentication)
	for i := uint32(0x82); i <= uint32(0x97); i++ {
		slots = append(slots, piv.Slot{Key: i})
	}

	for _, s := range slots {

		var pubKey crypto.PublicKey
		userCert, err := yk.Certificate(s)
		if err != nil {
			t.Errorf("%x USER CERT ERROR: %+v", s.Key, err)
		} else {
			t.Logf("%x subject: %+v", s.Key, userCert.Subject.String())
			pubKey = userCert.PublicKey
		}

		attestCert, err := yk.Attest(s)
		if err != nil {
			t.Errorf("%x ATEST CERT ERROR: %+v", s.Key, err)
		} else {
			t.Logf("%x subject: %+v", s.Key, attestCert.Subject.String())
			pubKey = attestCert.PublicKey
		}

		if pubKey != nil {
			privKey, err := yk.PrivateKey(s, pubKey, piv.KeyAuth{PIN: piv.DefaultPIN})
			if err != nil {
				t.Errorf("%x PRIV KEY ERROR: %+v", s.Key, err)
			} else {
				t.Logf("%x priv key: %+v", s.Key, privKey)
			}
		}
	}

	// Generate a private key on the YubiKey.
	pubKey, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
	})
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
	os.WriteFile("/tmp/yubiKeyAttestationCert.der", yubiKeyAttestationCert.Raw, 0666)

	slotAttestationCertificate, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Slot attestation cert: ")
	dumpCert(slotAttestationCertificate, t)
	os.WriteFile("/tmp/slotKeyAttestationCert.der", slotAttestationCertificate.Raw, 0666)

	// Import key
	unsafeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := yk.SetPrivateKeyInsecure(piv.DefaultManagementKey, piv.SlotKeyManagement, unsafeKey, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
	}); err != nil {
		t.Fatalf("Cant import ECC key: %+v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	selfSignedCertBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, unsafeKey.Public(), unsafeKey)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	selfSignedCert, err := x509.ParseCertificate(selfSignedCertBytes)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	yk.SetCertificate(piv.DefaultManagementKey, piv.SlotKeyManagement, selfSignedCert)
}

func dumpCert(cert *x509.Certificate, t *testing.T) {
	t.Logf("Subject name: %s", cert.Subject.String())
	t.Logf("Issuer name: %s", cert.Issuer.String())
	t.Logf("Serial: %s", cert.SerialNumber.String())
}
