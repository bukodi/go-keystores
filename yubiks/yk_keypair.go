package yubiks

import (
	"crypto"
	"crypto/ecdsa"
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
	keyUsage     map[keystores.KeyUsage]bool
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

func (kp YkKeyPair) KeyUsage() map[keystores.KeyUsage]bool {
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

func (kp YkKeyPair) ECDH(remote *ecdsa.PublicKey) ([]byte, error) {
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

func (kp YkKeyPair) SetLabel(label string) error {
	//TODO implement me
	panic("implement me")
}

func (kp YkKeyPair) Attestation(nonce []byte) (att keystores.Attestation, err error) {
	//TODO implement me
	panic("implement me")
}
