package keystores

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

var (
	ErrOperationNotSupportedByKeyPair = errors.New("operation not supported by key pair")
)

type KeyPairId string

type GenKeyPairOpts struct {
	Algorithm  KeyAlgorithm
	Label      string
	KeyUsage   x509.KeyUsage
	Exportable bool
	Ephemeral  bool
}

type KeyPair interface {
	Id() KeyPairId
	Label() string
	Algorithm() KeyAlgorithm
	KeyUsage() x509.KeyUsage
	KeyStore() KeyStore
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
	ExportPrivate() (der []byte, err error)
	ExportPublic() (der []byte, err error)
	Destroy() error
	Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error)
}

func GenerateKeyPairIdFromPubKey(pubKey crypto.PublicKey) (KeyPairId, error) {
	pkcs8DerBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", ErrorHandler(err)
	}
	sum := sha256.Sum256(pkcs8DerBytes)
	id := fmt.Sprintf("%.02x", sum)
	return KeyPairId(id), nil
}
