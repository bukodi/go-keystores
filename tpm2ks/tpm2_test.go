package tpm2ks

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"log"
	"os"
	"testing"
)

const PASSWORD = "" //"Passw0rd"

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

	if value, err := tpm2.NVRead(f, tpmutil.Handle(0x1c00002)); err != nil {
		t.Logf("Can't read Manufacturer certificate for EK RSA: %v", err)
	} else {
		t.Logf("Manufacturer certificate for EK RSA: \n%s\n", base64.StdEncoding.EncodeToString(value))
		os.WriteFile("/tmp/tpm_ek_rsa.cer", value, 0644)
	}

	if value, err := tpm2.NVRead(f, tpmutil.Handle(0x1c0000a)); err != nil {
		t.Logf("Can't read Manufacturer certificate for EK ECC: %v", err)
	} else {
		t.Logf("Manufacturer certificate for EK ECC: \n%s\n", base64.StdEncoding.EncodeToString(value))
		os.WriteFile("/tmp/tpm_ek_ecc.cer", value, 0644)

	}

	if manu, err := tpm2.GetManufacturer(f); err != nil {
		log.Fatalf("opening tpm: %v", err)
	} else {
		fmt.Printf("Manufacturer: %s\n%v\n", string(manu), manu)
	}

	ekCtx, _, err := EndorsementKey(f)
	//ekCtx, _, err := EndorsementKeyECC(f)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	t.Log(printKey(f, ekCtx, "Endorsement Key"))

	//srkCtx, err := StorageRootKey(f)
	srkCtx, err := StorageRootKeyECP256(f)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	t.Log(printKey(f, srkCtx, "Storage Root Key"))

	aikCtx, aikPubBlob, aikNameData, err := AttestestationIdentityKey(f, srkCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	secretNonce := []byte("123")
	credBlob, encSecret, err := CreateChallenge(f, ekCtx, aikPubBlob, aikNameData, secretNonce)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	decodedNonce, err := ActivateCredential(f, ekCtx, aikCtx, credBlob, encSecret)
	if err != nil {
		t.Fatalf("%#v", err)
	} else if !bytes.Equal(decodedNonce, secretNonce) {
		t.Fatalf("Nonce mismatch")
	} else {
		t.Logf("Nonce match")
	}

	appKeyCtx, appKeyHash, appKeyTicket, err := CreateAppKey(f, srkCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	t.Logf(printKey(f, srkCtx, "App signing Key"))

	digest := sha256.Sum256([]byte("Hello world!"))
	sigBytes, pubKey, err := SignWithAppKey(f, appKeyCtx, digest[:])
	if err != nil {
		t.Fatalf("%#v", err)
	}
	if ecdsa.VerifyASN1(pubKey.(*ecdsa.PublicKey), digest[:], sigBytes) {
		t.Log("Signature verified")
	} else {
		t.Fatalf("Verification failed")
	}

	attestData, sigData, err := CertifyAppKey(f, appKeyCtx, appKeyHash, appKeyTicket, aikCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	_, aikPub, err := getPublic(f, aikCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}

	pubKeyObj, _, err := getPublic(f, appKeyCtx)
	if err != nil {
		t.Fatalf("%#v", err)
	}
	pubBlob, err := pubKeyObj.Encode()
	if err != nil {
		t.Fatalf("%#v", err)
	}

	err = VerifyAttestation(pubBlob, attestData, sigData, aikPub)
	if err != nil {
		t.Fatalf("%#v", err)
	} else {
		t.Logf("Attestation signature verified")
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

func EndorsementKeyECC(f io.ReadWriter) (ekCtx []byte, ekPub crypto.PublicKey, err error) {
	tmpl := client.DefaultEKTemplateECC()
	/*tmpl := tpm2.Public{
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
	}*/

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

	srk, _, err := tpm2.CreatePrimary(f, tpm2.HandleOwner, tpm2.PCRSelection{}, "", PASSWORD, tmpl)
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

func StorageRootKeyECP256(f io.ReadWriter) (srkCtx []byte, err error) {
	tmpl := client.SRKTemplateECC()
	/*tmpl := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
			tpm2.FlagFixedParent | // Key can't change parent.
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
			tpm2.FlagUserWithAuth | // Uses (empty) password.
			tpm2.FlagNoDA | // This flag doesn't do anything, but it's in the spec.
			tpm2.FlagRestricted | // Key used for TPM challenges, not general decryption.
			tpm2.FlagDecrypt, // Key can be used to decrypt data.
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}*/

	srk, _, err := tpm2.CreatePrimary(f, tpm2.HandleOwner, tpm2.PCRSelection{}, "", PASSWORD, tmpl)
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

	aikPrivBlob, aikPubBlob, _, _, _, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, PASSWORD, PASSWORD, tmpl)
	if err != nil {
		return nil, nil, nil, keystores.ErrorHandler(err)
	}
	aik, aikNameData, err := tpm2.Load(f, srk, PASSWORD, aikPubBlob, aikPrivBlob)
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

func CreateChallenge(f io.ReadWriter, ekCtx []byte, aikPubBlob, aikNameData []byte, secret []byte) (credBlob, encSecret []byte, err error) {
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
	fmt.Printf("AIK key attributes: 0x08%x\n", pub.Attributes)

	// Generate a challenge for the name.
	//secret := []byte("The quick brown fox jumps over the lazy dog")
	symBlockSize := 16
	credBlob, encSecret, err = credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	return credBlob, encSecret, nil
}

func ActivateCredential(f io.ReadWriter, ekCtx []byte, aikCtx []byte, credBlob, encSecret []byte) (secretNonce []byte, err error) {
	ek, err := tpm2.ContextLoad(f, ekCtx)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, ek)

	aik, err := tpm2.ContextLoad(f, aikCtx)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
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
		return nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, session)

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, _, err := tpm2.PolicySecret(f, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(f, auths, aik, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	return out, nil
}

func ImportECDSAKey(f io.ReadWriter, srkCtx []byte, pk *ecdsa.PrivateKey) (impKeyCtx []byte, err error) {
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, srk)

	public := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   tpm2.ECPoint{XRaw: pk.PublicKey.X.Bytes(), YRaw: pk.PublicKey.Y.Bytes()},
		},
	}
	private := tpm2.Private{
		Type:      tpm2.AlgECC,
		Sensitive: pk.D.Bytes(),
	}

	subjectHandle, _, err := tpm2.LoadExternal(f, public, private, tpm2.HandleNull)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	defer tpm2.FlushContext(f, subjectHandle)

	// Write key context to disk.
	impKeyCtx, err = tpm2.ContextSave(f, subjectHandle)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	return impKeyCtx, nil
}

func CreateAppKey(f io.ReadWriter, srkCtx []byte) (appKeyCtx []byte, appKeyHash []byte, appKeyTicket tpm2.Ticket, err error) {
	srk, err := tpm2.ContextLoad(f, srkCtx)
	if err != nil {
		return nil, nil, appKeyTicket, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, srk)

	// Same as the AIK, but without the "restricted" flag.
	tmpl := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
			tpm2.FlagFixedParent | // Key can't change parent.
			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
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

	privBlob, pubBlob, _, appKeyHash, appKeyTicket, err := tpm2.CreateKey(f, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		return nil, nil, appKeyTicket, keystores.ErrorHandler(err)
	}
	fmt.Printf("PubBlob after creation: %s\n", hex.EncodeToString(pubBlob))
	appKey, _, err := tpm2.Load(f, srk, "", pubBlob, privBlob)
	if err != nil {
		return nil, nil, appKeyTicket, keystores.ErrorHandler(err)
	}

	// Write key context to disk.
	appKeyCtx, err = tpm2.ContextSave(f, appKey)
	if err != nil {
		return nil, nil, appKeyTicket, keystores.ErrorHandler(err)
	}

	return appKeyCtx, appKeyHash, appKeyTicket, nil
}

func SignWithAppKey(f io.ReadWriter, appKeyCtx []byte, digest []byte) (asn1Sig []byte, pubKey crypto.PublicKey, err error) {
	appKey, err := tpm2.ContextLoad(f, appKeyCtx)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, appKey)

	tpmPub, _, _, err := tpm2.ReadPublic(f, appKey)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	sigParams := tpmPub.ECCParameters.Sign
	cryptoPub, err := tpmPub.Key()
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}

	sig, err := tpm2.Sign(f, appKey, PASSWORD, digest, nil, sigParams)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}

	asn1Sig = ecdhSignatureToASN1(sig.ECC.R, sig.ECC.S)
	if asn1Sig == nil {
		return nil, nil, keystores.ErrorHandler(fmt.Errorf("can't marshall ECDSA r s"))
	} else {
		return asn1Sig, cryptoPub, nil
	}
}

func CertifyAppKey(f io.ReadWriter, appKeyCtx []byte, appKeyHash []byte, appKeyTicket tpm2.Ticket, aikCtx []byte) (attestData []byte, sigData []byte, err error) {
	appKey, err := tpm2.ContextLoad(f, appKeyCtx)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, appKey)
	aik, err := tpm2.ContextLoad(f, aikCtx)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, aik)

	aikTPMPub, _, _, err := tpm2.ReadPublic(f, aik)
	if err != nil {
		log.Fatalf("read aik pub: %v", err)
	}
	sigParams := aikTPMPub.ECCParameters.Sign
	aikPub, err := aikTPMPub.Key()
	if err != nil {
		log.Fatalf("getting aik public key")
	}

	attestData, sigData, err = tpm2.CertifyCreation(f, "", appKey, aik, nil, appKeyHash, *sigParams, appKeyTicket)
	if err != nil {
		log.Fatalf("certify creation: %v", err)
	}
	_ = aikPub

	sigObj, err := tpm2.DecodeSignature(bytes.NewBuffer(sigData))
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}

	asn1Sig := ecdhSignatureToASN1(sigObj.ECC.R, sigObj.ECC.S)

	return attestData, asn1Sig, nil
}

func getPublic(f io.ReadWriter, ctx []byte) (pubObj *tpm2.Public, pubKey crypto.PublicKey, err error) {
	tpmKey, err := tpm2.ContextLoad(f, ctx)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	defer tpm2.FlushContext(f, tpmKey)

	tpmPubKey, _, _, err := tpm2.ReadPublic(f, tpmKey)
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	pubKey, err = tpmPubKey.Key()
	if err != nil {
		return nil, nil, keystores.ErrorHandler(err)
	}
	return &tpmPubKey, pubKey, nil
}

func VerifyAttestation(pubBlob []byte, attestData []byte, sigData []byte, aikPub crypto.PublicKey) (err error) {
	aikECDSAPub, ok := aikPub.(*ecdsa.PublicKey)
	if !ok {
		return keystores.ErrorHandler(fmt.Errorf("expected ecdsa public key, got: %T", aikPub))
	}

	digest := sha256.Sum256(attestData)
	// Verify attested data is signed by the EK public key.
	if !ecdsa.VerifyASN1(aikECDSAPub, digest[:], sigData) {
		return keystores.ErrorHandler(fmt.Errorf("signature didn't match"))
	}

	// Verify the signed attestation was for this public blob.
	a, err := tpm2.DecodeAttestationData(attestData)
	if err != nil {
		log.Fatalf("decode attestation: %v", err)
	}

	pubDigest := sha256.Sum256(pubBlob)
	if !bytes.Equal(a.AttestedCreationInfo.Name.Digest.Value, pubDigest[:]) {
		log.Fatalf("attestation was not for public blob")
	}

	// Decode public key and inspect key attributes.
	tpmPub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Fatalf("decode public blob: %v", err)
	}
	pub, err := tpmPub.Key()
	if err != nil {
		log.Fatalf("decode public key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("encoding public key: %v", err)
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	fmt.Printf("Key attributes: 0x%08x\n", tpmPub.Attributes)
	pem.Encode(os.Stdout, b)

	return nil
}

func TestECDSASign(t *testing.T) {
	f, err := openTpm()
	if err != nil {
		t.Fatalf("%#v", err)
	}
	defer f.Close()

	srkCtx, err := StorageRootKeyECP256(f)
	if err != nil {
		t.Fatalf("%s\n%#v", err.Error(), err)
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyCtx, err := ImportECDSAKey(f, srkCtx, pk)
	if err != nil {
		t.Fatalf("%s\n%#v", err.Error(), err)
	}

	t.Log(printKey(f, keyCtx, "Imported Key"))
	_ = keyCtx
}
