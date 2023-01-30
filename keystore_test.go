package keystores

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"testing"
)

func SignVerifyForTests(t *testing.T, kp KeyPair) {
	digest := sha256.Sum256([]byte("hello world\n"))

	signature, err := kp.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Digest : %+v", digest)
	t.Logf("Signature: %+v", signature)
	t.Logf("Sign as b64: %s", base64.StdEncoding.EncodeToString(signature))

	t.Logf("%+v", kp)

	err = kp.Verify(signature, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("Signature is valid")
	}
}

func TestEnsureClosed(t *testing.T) {
	type args struct {
		obj Openable
	}
	var tests []struct {
		name    string
		args    args
		wantErr bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EnsureClosed(tt.args.obj); (err != nil) != tt.wantErr {
				t.Errorf("EnsureClosed() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnsureOpen(t *testing.T) {
	type args struct {
		obj Openable
	}
	var tests []struct {
		name    string
		args    args
		wantErr bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EnsureOpen(tt.args.obj); (err != nil) != tt.wantErr {
				t.Errorf("EnsureOpen() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateKeyPairIdFromPubKey(t *testing.T) {
	type args struct {
		pubKey crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    KeyPairId
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKeyPairIdFromPubKey(tt.args.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPairIdFromPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateKeyPairIdFromPubKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyAlgorithm_Equal(t *testing.T) {
	type fields struct {
		Oid       asn1.ObjectIdentifier
		KeyLength int
		Name      string
	}
	type args struct {
		other KeyAlgorithm
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka := KeyAlgorithm{
				Oid:          tt.fields.Oid,
				RSAKeyLength: tt.fields.KeyLength,
				Name:         tt.fields.Name,
			}
			if got := ka.Equal(tt.args.other); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyAlgorithm_String(t *testing.T) {
	type fields struct {
		Oid       asn1.ObjectIdentifier
		KeyLength int
		Name      string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka := KeyAlgorithm{
				Oid:          tt.fields.Oid,
				RSAKeyLength: tt.fields.KeyLength,
				Name:         tt.fields.Name,
			}
			if got := ka.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustClosed(t *testing.T) {
	type args struct {
		obj Openable
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}

func Test_defaultErrorHandler(t *testing.T) {
	type args struct {
		err     error
		context []interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := defaultErrorHandler(tt.args.err, tt.args.context...); (err != nil) != tt.wantErr {
				t.Errorf("defaultErrorHandler() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
