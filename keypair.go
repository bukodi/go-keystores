package keystores

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	ErrOperationNotSupportedByKeyPair = errors.New("operation not supported by key pair")
)

type KeyPairId string

func PublicKeyFromPrivate(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	type i1 interface {
		Public() crypto.PublicKey
	}

	if o1, ok := privKey.(i1); ok {
		pubKey := o1.Public()
		return pubKey, nil
	} else {
		return nil, ErrorHandler(fmt.Errorf("%T has not Public() function", privKey))
	}
}

func IdFromPublicKey(pubKey crypto.PublicKey) (KeyPairId, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", ErrorHandler(err)
	}
	sum := sha256.Sum256(bytes)
	return KeyPairId(hex.EncodeToString(sum[:])), nil
}

type KeyPair interface {
	Id() KeyPairId
	Label() string
	SetLabel(label string) error
	Algorithm() KeyAlgorithm
	KeyUsage() map[KeyUsage]bool
	KeyStore() KeyStore
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
	ExportPrivate() (privKey crypto.PrivateKey, err error)
	Destroy() error
	Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error)
	ECDH(remote *ecdsa.PublicKey) ([]byte, error)
	Attestation(nonce []byte) (att Attestation, err error)
}

type AsyncKeyPair interface {
	Id(ctx context.Context) <-chan KeyPairId
	Label(ctx context.Context) <-chan string
	SetLabel(ctx context.Context, label string) (errCh <-chan error)
	Algorithm(ctx context.Context) <-chan KeyAlgorithm
	KeyUsage(ctx context.Context) <-chan []KeyUsage
	KeyStore(ctx context.Context) <-chan AsyncKeyStore
	Public(ctx context.Context) <-chan crypto.PublicKey
	Sign(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signatureCh <-chan []byte, errCh <-chan error)
	Decrypt(ctx context.Context, rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintextCh <-chan []byte, errCh <-chan error)
	ExportPrivate(ctx context.Context) (privKeyCh <-chan crypto.PrivateKey, errCh <-chan error)
	Destroy(ctx context.Context) <-chan error
	Verify(ctx context.Context, signature []byte, digest []byte, opts crypto.SignerOpts) <-chan error
	Attestation(ctx context.Context, nonce []byte) (att <-chan Attestation, errCh <-chan error)
}

// GenKeyPairOpts controls the key pair generation or import
type GenKeyPairOpts struct {
	Algorithm  KeyAlgorithm
	Label      string
	KeyUsage   map[KeyUsage]bool
	Exportable bool
	Ephemeral  bool
}

func GenerateKeyPairIdFromPubKey(pubKey crypto.PublicKey) (KeyPairId, error) {
	pkcs8DerBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", ErrorHandler(err)
	}
	sum := sha256.Sum256(pkcs8DerBytes)
	id := hex.EncodeToString(sum[:])
	return KeyPairId(id), nil
}
