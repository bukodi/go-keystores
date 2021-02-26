package keystores

import "context"

type KeyStore interface {
	SupportedPrivateKeyAlgorithms() []KeyAlgorithm
	KeyPairs() []KeyPair
	CreateKeyPair(privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
	ImportKeyPair(der []byte) (kp KeyPair, err error)
}

type AsyncKeyStore interface {
	AsyncCreateKeyPair(ctx context.Context, privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error)
}
