package tpm2ks

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestTPM2LowLevel(t *testing.T) {
	EndorsementKey()
	StorageRootKey()
	AttestestationIdentityKey()
}

func EndorsementKey() {
	f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer f.Close()

	if manu, err := tpm2.GetManufacturer(f); err != nil {
		log.Fatalf("opening tpm: %v", err)
	} else {
		fmt.Printf("Manufacturer: %s\n%v\n", string(manu), manu)
	}

	tmpl := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
			tpm2.FlagFixedParent | // Key can't change parent.
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
			tpm2.FlagAdminWithPolicy | // Key has an authPolicy.
			tpm2.FlagRestricted | // Key used for TPM challenges, not general decryption.
			tpm2.FlagDecrypt, // Key can be used to decrypt data.
		AuthPolicy: []byte{
			// TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
			// Endorsement hierarchy must be unlocked to use this key.
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	ek, pub, err := tpm2.CreatePrimary(f, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("creating ek: %v", err)
	}
	out, err := tpm2.ContextSave(f, ek)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("ek.ctx", out, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("encoding public key: %v", err)
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	pem.Encode(os.Stdout, b)
}

func StorageRootKey() {
	f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer f.Close()

	tmpl := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
			tpm2.FlagFixedParent | // Key can't change parent.
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
			tpm2.FlagUserWithAuth | // Uses (empty) password.
			tpm2.FlagNoDA | // This flag doesn't do anything, but it's in the spec.
			tpm2.FlagRestricted | // Key used for TPM challenges, not general decryption.
			tpm2.FlagDecrypt, // Key can be used to decrypt data.
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	srk, _, err := tpm2.CreatePrimary(f, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("creating srk: %v", err)
	}
	out, err := tpm2.ContextSave(f, srk)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("srk.ctx", out, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}
}

func AttestestationIdentityKey() {
	f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("opening tpm: %v", err)
	}
	defer f.Close()

	srkCtx, err := ioutil.ReadFile("srk.ctx")
	if err != nil {
		log.Fatalf("read srk: %v", err)
	}
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		log.Fatalf("load srk: %v", err)
	}

	ekCtx, err := ioutil.ReadFile("ek.ctx")
	if err != nil {
		log.Fatalf("read ek: %v", err)
	}
	ek, err := tpm2.ContextLoad(f, ekCtx)
	if err != nil {
		log.Fatalf("load ek: %v", err)
	}

	tmpl := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
			tpm2.FlagFixedParent | // Key can't change parent.
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
			tpm2.FlagRestricted | // Key used to sign TPM messages, not external ones.
			tpm2.FlagUserWithAuth | // Uses (empty) password.
			tpm2.FlagSign, // Key can be used to sign data.
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		log.Fatalf("create aik: %v", err)
	}
	aik, nameData, err := tpm2.Load(f, srk, "", pubBlob, privBlob)
	if err != nil {
		log.Fatalf("load aik: %v", err)
	}

	aikCtx, err := tpm2.ContextSave(f, aik)
	if err != nil {
		log.Fatalf("saving context: %v", err)
	}
	if err := ioutil.WriteFile("aik.ctx", aikCtx, 0644); err != nil {
		log.Fatalf("writing context: %v", err)
	}

	ekTPMPub, _, _, err := tpm2.ReadPublic(f, ek)
	if err != nil {
		log.Fatalf("read ek public: %v", err)
	}
	ekPub, err := ekTPMPub.Key()
	if err != nil {
		log.Fatalf("decode ek public key: %v", err)
	}

	// Verify digest matches the public blob that was provided.
	name, err := tpm2.DecodeName(bytes.NewBuffer(nameData))
	if err != nil {
		log.Fatalf("unpacking name: %v", err)
	}
	if name.Digest == nil {
		log.Fatalf("name was not a digest")
	}
	h, err := name.Digest.Alg.Hash()
	if err != nil {
		log.Fatalf("failed to get name hash: %v", err)
	}
	pubHash := h.New()
	pubHash.Write(pubBlob)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, pubDigest) {
		log.Fatalf("name was not for public blob")
	}

	// Inspect key attributes.
	pub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Fatalf("decode public blob: %v", err)
	}
	fmt.Printf("Key attributes: 0x08%x\n", pub.Attributes)

	// Generate a challenge for the name.
	secret := []byte("The quick brown fox jumps over the lazy dog")
	symBlockSize := 16
	credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		log.Fatalf("generate credential: %v", err)
	}

	session, _, err := tpm2.StartAuthSession(f,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		log.Fatalf("creating auth session: %v", err)
	}

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(f, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		log.Fatalf("policy secret failed: %v", err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(f, auths, aik, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		log.Fatalf("activate credential: %v", err)
	}
	fmt.Printf("%s\n", out)
}
