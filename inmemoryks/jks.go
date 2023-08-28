package inmemoryks

import (
	"crypto/x509"
	"github.com/bukodi/go-keystores"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"io"
	"time"
)

func (imks *InMemoryKeyStore) SaveAsJKS(w io.Writer, password []byte) error {
	ks := jks.New()
	kps, errs := imks.KeyPairs(false)
	_ = errs // Ignore errors
	for _, kp := range kps {
		alias := kp.Label()
		privKey, err := kp.ExportPrivate()
		if err != nil {
			continue
		}
		privKeyPkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			continue
		}
		pke := jks.PrivateKeyEntry{
			CreationTime:     time.Now(),
			PrivateKey:       privKeyPkcs8,
			CertificateChain: []jks.Certificate{},
		}
		err = ks.SetPrivateKeyEntry(alias, pke, password)
		if err != nil {
			return keystores.ErrorHandler(err)
		}
	}

	err := ks.Store(w, password)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return nil
}

func (imks *InMemoryKeyStore) LoadFromJKS(r io.Reader, password []byte) error {
	ks := jks.New()
	err := ks.Load(r, password)
	if err != nil {
		return keystores.ErrorHandler(err)
	}

	for _, alias := range ks.Aliases() {
		if ks.IsPrivateKeyEntry(alias) {
			pke, err := ks.GetPrivateKeyEntry(alias, password)
			if err != nil {
				return keystores.ErrorHandler(err)
			}
			privKey, err := x509.ParsePKCS8PrivateKey(pke.PrivateKey)
			if err != nil {
				return keystores.ErrorHandler(err)
			}
			kp, err := imks.ImportKeyPair(privKey, keystores.GenKeyPairOpts{})
			if err != nil {
				return keystores.ErrorHandler(err)
			}
			err = kp.SetLabel(alias)
			if err != nil {
				return keystores.ErrorHandler(err)
			}
		}
	}
	return nil
}
