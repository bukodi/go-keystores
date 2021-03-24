package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
	"math/big"
	"strings"
)

func main() {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		fmt.Printf("%+v", errors.WithStack(err)) // ...
		return
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		fmt.Printf("Cahck card: %s\n", card)
		if strings.Contains(strings.ToLower(card), "vmware") || strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				fmt.Printf("%+v", errors.WithStack(err)) // ...
				return
			}
			break
		}
	}
	if yk == nil {
		fmt.Printf("Yubikey not found\n") // ...
		return
	}

	if serial, err := yk.Serial(); err != nil {
		fmt.Printf("%+v\n", errors.WithStack(err)) // ...
		return
	} else {
		fmt.Printf("Yubikey serial: %v\n", serial)
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
		fmt.Printf("%+v", errors.WithStack(err))
		return
	} else {
		fmt.Printf("Metadata: %#v\n", md)
	}

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyCached,
	}
	pubKey, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
	if err != nil {
		fmt.Printf("%+v\n", errors.WithStack(err)) // ...
		return
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	privKey, err := yk.PrivateKey(piv.SlotAuthentication, pubKey, auth)
	if err != nil {
		fmt.Printf("%+v\n", errors.WithStack(err)) // ...
		return
	}
	fmt.Printf("Priv key created:\n %#v\n", privKey)

	// Use private key to sign or decrypt.
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Printf("public key is not an ecdsa key\n")
		return
	}
	data := sha256.Sum256([]byte("hello"))
	s, ok := privKey.(crypto.Signer)
	if !ok {
		fmt.Printf("expected private key to implement crypto.Signer\n")
		return
	}
	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		fmt.Printf("signing failed: %+v\n", errors.WithStack(err))
		return
	} else {
		fmt.Printf(`Signature of "hello": %+v`+"\n", out)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		fmt.Printf("unmarshaling signature: %v\n", errors.WithStack(err))
		return
	}
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		fmt.Printf("signature didn't match\n")
		return
	} else {
		fmt.Printf("Signature verified.\n")
	}

	// Get the YubiKey's attestation certificate, which is signed by Yubico.
	yubiKeyAttestationCert, err := yk.AttestationCertificate()
	if err != nil {
		fmt.Printf("%+v", errors.WithStack(err))
		return
	}
	fmt.Printf("Attestation cert:\n")
	dumpCert(yubiKeyAttestationCert)
	//os.WriteFile("/tmp/yubiKeyAttestationCert.der", yubiKeyAttestationCert.Raw, 0666)

	slotAttestationCertificate, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		fmt.Printf("%+v", errors.WithStack(err))
		return
	}
	fmt.Printf("Slot attestation cert: \n")
	dumpCert(slotAttestationCertificate)
	//os.WriteFile("/tmp/slotKeyAttestationCert.der", slotAttestationCertificate.Raw, 0666)

}

func dumpCert(cert *x509.Certificate) {
	fmt.Printf("Subject name: %s\n", cert.Subject.String())
	fmt.Printf("Issuer name: %s\n", cert.Issuer.String())
	fmt.Printf("Serial: %s\n", cert.SerialNumber.String())
}
