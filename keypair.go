package keystores

import (
	"crypto"
	"errors"
	"io"
)

var (
	ErrOperationNotSupportedByKeyPair = errors.New("operation not supported by key pair")
)

type KeyPairId string

type KeyPair interface {
	Id() KeyPairId
	Label() string
	Algorithm() KeyAlgorithm
	KeyStore() KeyStore
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
	ExportPrivate() (der []byte, err error)
	ExportPublic() (der []byte, err error)
	Destroy()
	Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error)
}
