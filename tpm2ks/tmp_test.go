package tpm2ks

import (
	"bytes"
	"crypto"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	"io"
	"log"
	"os"
	"testing"
)

var tpmFile io.ReadWriteCloser

func openTpm() (io.ReadWriteCloser, error) {
	if f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0); err == nil {
		return f, nil
	} else if os.IsNotExist(err) {
		// Get simulated TPM.
		if sim, err := simulator.Get(); err != nil {
			return nil, fmt.Errorf("failed to get TPM simulator: %w", err)
		} else {
			return sim, nil
		}
	} else {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
}

func TestTPM2LowLevel(t *testing.T) {
	f, err := openTpm()
	if err != nil {
		t.Fatalf("%#v", err)
	}
	defer f.Close()
	if manu, err := tpm2.GetManufacturer(f); err != nil {
		log.Fatalf("opening tpm: %v", err)
	} else {
		fmt.Printf("Manufacturer: %s\n%v\n", string(manu), manu)
	}

	ekCtx, _, err := EndorsementKey(f)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	srkCtx, err := StorageRootKey(f)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	aikCtx, aikPubBlob, aikNameData, err := AttestestationIdentityKey(f, srkCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	credBlob, encSecret, err := CreateChallenge(f, ekCtx, aikPubBlob, aikNameData)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	err = StartSession(f, ekCtx, aikCtx, credBlob, encSecret)
	if err != nil {
		t.Fatalf("%#v", err)
	}
}

func EndorsementKey(f io.ReadWriter) (ekCtx []byte, ekPub crypto.PublicKey, err error) {
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
	defer tpm2.FlushContext(f, ek)
	out, err := tpm2.ContextSave(f, ek)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	return out, pub, nil
}

func StorageRootKey(f io.ReadWriter) (srkCtx []byte, err error) {
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
		return nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, srk)

	out, err := tpm2.ContextSave(f, srk)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	return out, nil
}

func AttestestationIdentityKey(f io.ReadWriter, srkCtx []byte) (aikCtx []byte, aikPubBlob []byte, aikNameData []byte, err error) {
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		return nil, nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, srk)

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

	aikPrivBlob, aikPubBlob, _, _, _, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		return nil, nil, nil, keystores.ErrorHandler(err)
	}
	aik, aikNameData, err := tpm2.Load(f, srk, "", aikPubBlob, aikPrivBlob)
	if err != nil {
		return nil, nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, aik)

	aikCtx, err = tpm2.ContextSave(f, aik)
	if err != nil {
		return nil, nil, nil, keystores.ErrorHandler(err)
	}
	return aikCtx, aikPubBlob, aikNameData, nil
}

func CreateChallenge(f io.ReadWriter, ekCtx []byte, aikPubBlob, aikNameData []byte) (credBlob, encSecret []byte, err error) {
	ek, err := tpm2.ContextLoad(f, ekCtx)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, ek)
	ekTPMPub, _, _, err := tpm2.ReadPublic(f, ek)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	ekPub, err := ekTPMPub.Key()
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}

	// Verify digest matches the public blob that was provided.
	name, err := tpm2.DecodeName(bytes.NewBuffer(aikNameData))
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	if name.Digest == nil {
		return nil, nil, keystores.ErrorHandler(fmt.Errorf("name was not a digest"))
	}
	h, err := name.Digest.Alg.Hash()
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	pubHash := h.New()
	pubHash.Write(aikPubBlob)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, pubDigest) {
		return nil, nil, keystores.ErrorHandler(fmt.Errorf("name was not for public blob"))
	}

	// Inspect key attributes.
	pub, err := tpm2.DecodePublic(aikPubBlob)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	fmt.Printf("Key attributes: 0x08%x\n", pub.Attributes)

	// Generate a challenge for the name.
	secret := []byte("The quick brown fox jumps over the lazy dog")
	symBlockSize := 16
	credBlob, encSecret, err = credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	return credBlob, encSecret, nil
}

func StartSession(f io.ReadWriter, ekCtx []byte, aikCtx []byte, credBlob, encSecret []byte) (err error) {
	ek, err := tpm2.ContextLoad(f, ekCtx)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, ek)

	aik, err := tpm2.ContextLoad(f, aikCtx)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, aik)

	session, _, err := tpm2.StartAuthSession(f,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, session)

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(f, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return keystores.ErrorHandler(err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(f, auths, aik, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	fmt.Printf("%s\n", out)
	return nil
}
