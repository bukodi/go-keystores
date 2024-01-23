package tpm2ks

import (
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

	// Create the SRK
	// Put a password on the SRK to test more of the flows.

	srkAuth := []byte("mySRK")
	createSRKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SRK name: %x", createSRKRsp.Name)
	defer func() {
		// Flush the SRK
		flushSRKCmd := tpm2.FlushContext{FlushHandle: createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

}
