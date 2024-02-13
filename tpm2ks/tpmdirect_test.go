package tpm2ks

import (
	"errors"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"testing"
)

func openTpmDirect() (transport.TPMCloser, error) {

	sim, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: sim,
	}, nil
}

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}

func TestDirectSealUnseal(t *testing.T) {

	thetpm, err := openTpmDirect()
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer thetpm.Close()

	sealedDataPub, sealeddataPriv, srkName, err := sealData(thetpm, []byte("Hello World"), []byte("myObjectAuth"))
	if err != nil {
		t.Fatalf("%+v", err)
	}
	t.Logf("SRK name: %x", srkName)
	t.Logf("Sealed data: \n%d bytes: %x\n%d bytes:%x\n", len(sealedDataPub), sealedDataPub, len(sealeddataPriv), sealeddataPriv)

	unsealedData, err := unsealData(thetpm, sealedDataPub, sealeddataPriv, []byte("myObjectAuth"))
	if err != nil {
		t.Fatalf("%+v", err)
	}
	t.Logf("Unsealed data: %s", unsealedData)
}

const srkAuthPassword = "mySRK"

func sealData(thetpm transport.TPM, data []byte, auth []byte) (sealedDataPub []byte, sealedDataPriv []byte, srkName tpm2.TPM2BName, err error) {
	// Create the SRK
	hSrk, srkName, err := createSRK(thetpm)
	if err != nil {
		return nil, nil, srkName, err
	}
	defer func() {
		// Flush the SRK
		flushSRKCmd := tpm2.FlushContext{FlushHandle: hSrk}
		if _, err2 := flushSRKCmd.Execute(thetpm); err2 != nil {
			err = errors.Join(err, err2)
		}
	}()

	// Create a sealed blob under the SRK
	createBlobCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: hSrk,
			Name:   srkName,
			//Auth:   tpm2.PasswordAuth([]byte(srkAuthPassword)),
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte(srkAuthPassword)), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.AuditExclusive()),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: auth,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}

	createBlobRsp, err := createBlobCmd.Execute(thetpm)
	if err != nil {
		return nil, nil, srkName, err
	}

	return createBlobRsp.OutPublic.Bytes(), createBlobRsp.OutPrivate.Buffer, srkName, nil
}

func unsealData(thetpm transport.TPM, sealedDataPub []byte, sealedDataPriv []byte, auth []byte) (data []byte, err error) {
	// Create the SRK
	hSrk, srkName, err := createSRK(thetpm)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Flush the SRK
		flushSRKCmd := tpm2.FlushContext{FlushHandle: hSrk}
		if _, err2 := flushSRKCmd.Execute(thetpm); err2 != nil {
			err = errors.Join(err, err2)
		}
	}()

	blobPrivate := tpm2.TPM2BPrivate{
		Buffer: sealedDataPriv,
	}

	blobPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](sealedDataPub)

	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: hSrk,
			Name:   srkName,
			//Auth:   tpm2.PasswordAuth([]byte(srkAuthPassword)),
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte(srkAuthPassword)), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.AuditExclusive()),
		},
		InPrivate: blobPrivate,
		InPublic:  blobPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err2 := flushBlobCmd.Execute(thetpm); err2 != nil {
			err = errors.Join(err, err2)
		}
	}()

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}
	unsealCmd.ItemHandle = tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth),
			tpm2.AESEncryption(128, tpm2.EncryptOut)),
	}
	unsealRsp, err := unsealCmd.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	return unsealRsp.OutData.Buffer, nil
}

func createSRK(thetpm transport.TPM) (hSrk tpm2.TPMHandle, srkName tpm2.TPM2BName, err error) {
	createSRKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(srkAuthPassword),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		return hSrk, srkName, err
	}

	/*readPublic := tpm2.ReadPublic{
		hSrk,
	}
	readPublicRsp, err := readPublic.Execute(thetpm)
	if err != nil {
		return hSrk, srkName, err
	}*/

	return createSRKRsp.ObjectHandle, createSRKRsp.Name, nil
}
