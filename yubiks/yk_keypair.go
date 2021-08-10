package yubiks

import (
	"crypto"
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	"io"
)

// Check whether implements the keystores.KeyPair interface
var _ keystores.KeyPair = &YkKeyPair{}

type YkKeyPair struct {
	keySore      *YkKeyStore
	slot         int
	pubKey       crypto.PublicKey
	id           keystores.KeyPairId
	keyAlgorithm keystores.KeyAlgorithm
	label        string
	keyUsage     x509.KeyUsage
}

func (kp YkKeyPair) Id() keystores.KeyPairId {
	panic("implement me")
}

func (kp YkKeyPair) Label() string {
	panic("implement me")
}

func (kp YkKeyPair) Algorithm() keystores.KeyAlgorithm {
	panic("implement me")
}

func (kp YkKeyPair) KeyUsage() x509.KeyUsage {
	panic("implement me")
}

func (kp YkKeyPair) KeyStore() keystores.KeyStore {
	panic("implement me")
}

func (kp YkKeyPair) Public() crypto.PublicKey {
	panic("implement me")
}

func (kp YkKeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("implement me")
}

func (kp YkKeyPair) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	panic("implement me")
}

func (kp YkKeyPair) ExportPrivate() (privKey crypto.PrivateKey, err error) {
	panic("implement me")
}

func (kp YkKeyPair) Destroy() error {
	panic("implement me")
}

func (kp YkKeyPair) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) (err error) {
	panic("implement me")
}
