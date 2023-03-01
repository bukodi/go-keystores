//go:build !windows
// +build !windows

package tpm2ks

import (
	"encoding/hex"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"testing"
)

var (
	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	// Shared SRK template based off of EK template and specified in:
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
)

func TestSealUnseal(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
func run() (retErr error) {
	tpmPath := "/dev/tpmrm0"
	// Open the TPM
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			retErr = fmt.Errorf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	// Create the parent key against which to seal the data
	srkPassword := ""
	srkTemplate = client.SRKTemplateECC()
	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", srkPassword, srkTemplate)
	if err != nil {
		return fmt.Errorf("can't create primary key: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, srkHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush SRK handle %q: %v", retErr, srkHandle, err)
		}
	}()
	fmt.Printf("Created parent key with handle: 0x%x\n", srkHandle)

	// Get the authorization policy that will protect the data to be sealed
	objectPassword := "objectPassword"
	sessHandle, policy, err := policyPCRPasswordSession(rwc, objectPassword)
	if err != nil {
		return fmt.Errorf("unable to get policy: %v", err)
	}
	if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
		return fmt.Errorf("unable to flush session: %v", err)
	}
	fmt.Printf("Created authorization policy: 0x%x\n", policy)

	// Seal the data to the parent key and the policy
	dataToSeal := []byte("secret")
	fmt.Printf("Data to be sealed: \n%s\n", hex.EncodeToString(dataToSeal))
	privateArea, publicArea, err := tpm2.Seal(rwc, srkHandle, srkPassword, objectPassword, policy, dataToSeal)
	if err != nil {
		return fmt.Errorf("unable to seal data: %v", err)
	}
	fmt.Printf("Sealed data: 0x%x\n", privateArea)
	fmt.Printf("Sealed data public and private:\n%s\n\n%s\n", hex.EncodeToString(publicArea), hex.EncodeToString(privateArea))

	//publicArea, _ = hex.DecodeString("0008000b0000001200208fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e001000202b3046c35e30c79b9d09d672d64d664b3ee9724741829a756bb8f6e6582af1ab")
	//privateArea, _ = hex.DecodeString("00208e7732c843d7cb45288164f7ad8713eeb7b39398ddd752fbd16d2addb140e80700104003c6232480d87fa1d63b0678cb60d770425331f63d08ca2554603cc30c3961a8262bcd8cf2941f2751c77dacbf2ea079e62aaf22c60ddf705fe719b4c61ae822e460847a4cfe312ab1671e0dc8fe5bb2ec38ba37189e03abcc4a74fefe5008")

	// Load the sealed data into the TPM.
	objectHandle, _, err := tpm2.Load(rwc, srkHandle, srkPassword, publicArea, privateArea)
	if err != nil {
		return fmt.Errorf("unable to load data: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, objectHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush object handle %q: %v", retErr, objectHandle, err)
		}
	}()
	fmt.Printf("Loaded sealed data with handle: 0x%x\n", objectHandle)

	// Unseal the data
	unsealedData, err := unseal(rwc, objectPassword, objectHandle)
	if err != nil {
		return fmt.Errorf("unable to unseal data: %v", err)
	}
	fmt.Printf("Unsealed data: 0x%x\n", unsealedData)

	// Try to unseal the data with the wrong password
	_, err = unseal(rwc, "wrong-password", objectHandle)
	fmt.Printf("Trying to unseal with wrong password resulted in: %v\n", err)

	return
}

// Returns the unsealed data
func unseal(rwc io.ReadWriteCloser, objectPassword string, objectHandle tpmutil.Handle) (data []byte, retErr error) {
	// Create the authorization session
	sessHandle, _, err := policyPCRPasswordSession(rwc, objectPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to get auth session: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
		}
	}()

	// Unseal the data
	unsealedData, err := tpm2.UnsealWithSession(rwc, sessHandle, objectHandle, objectPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to unseal data: %v", err)
	}
	return unsealedData, nil
}

// Returns session handle and policy digest.
func policyPCRPasswordSession(rwc io.ReadWriteCloser, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	// FYI, this is not a very secure session.
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	defer func() {
		if sessHandle != tpm2.HandleNull && err != nil {
			if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
				retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
			}
		}
	}()

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPassword(rwc, sessHandle); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
	}

	policy, err = tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}
