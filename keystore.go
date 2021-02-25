package keystores

import (
	"crypto"
	"encoding/asn1"
	"io"
)

type KeyAlgorithm struct {
	oid       asn1.ObjectIdentifier
	keyLength int
	name      string
}

var KeyAlgRSA2048 = KeyAlgorithm{
	oid:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
	keyLength: 2048,
	name:      "RSA-2048",
}
var KeyAlgECP256 = KeyAlgorithm{
	oid:  asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	name: "NIST P-256",
}
var KeyAlgEd25519 = KeyAlgorithm{
	oid:  asn1.ObjectIdentifier{1, 3, 101, 112},
	name: "Ed25519",
}

func (ka KeyAlgorithm) Equal(other KeyAlgorithm) bool {
	if !ka.oid.Equal(other.oid) {
		return false
	}
	if ka.keyLength != other.keyLength {
		return false
	}
	return true
}

func (ka KeyAlgorithm) Name() string {
	return ka.name
}

type KeyStore interface {
	SupportedPrivateKeyAlgorithms() []KeyAlgorithm
	KeyPairs() []KeyPair
	CreateKeyPair(privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
	ImportKeyPair(der []byte) (kp KeyPair, err error)
}

type KeyPairId string

type KeyPair interface {
	Id() KeyPairId
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
