package yubiks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/go-piv/piv-go/piv"
)

type YkKeyStore struct {
	provider *YkProvider
	pivyk    *piv.YubiKey
	serial   string
	cardName string
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &YkKeyStore{}

func (ks *YkKeyStore) Id() string {
	return ks.serial
}

func (ks *YkKeyStore) Name() string {
	return fmt.Sprintf("%s (#%s)", ks.cardName, ks.serial)
}

func (ks *YkKeyStore) Open() error {
	return nil
}

func (ks *YkKeyStore) Close() error {
	return nil
}

func (ks *YkKeyStore) IsOpen() bool {
	return true
}

func (ks *YkKeyStore) Reload() error {
	return nil
}

func (ks *YkKeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{
		keystores.KeyAlgRSA2048,
		keystores.KeyAlgRSA3072,
		keystores.KeyAlgRSA4096,
		keystores.KeyAlgECP224,
		keystores.KeyAlgECP256,
		keystores.KeyAlgECP384,
		keystores.KeyAlgECP521,
	}
	return algs
}

func (ks *YkKeyStore) KeyPairById(id keystores.KeyPairId) keystores.KeyPair {
	panic("implement me")
}

func (ks *YkKeyStore) KeyPairs(reload bool) (keyPairs map[keystores.KeyPairId]keystores.KeyPair, errs error) {
	//ks.pivyk.Attest()
	panic("implement me")
}

func labelToSlotId(label string) (piv.Slot, error) {
	return piv.SlotAuthentication, nil
}

func (ks *YkKeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	//TODO: support special key gen options for yubikey
	if opts.Algorithm.RSAKeyLength > 0 {
		pivSlot, err := labelToSlotId(opts.Label)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		pivKeyOpts := piv.Key{
			Algorithm:   piv.AlgorithmRSA1024,
			TouchPolicy: piv.TouchPolicyNever,
			PINPolicy:   piv.PINPolicyNever,
		}

		pubKey, err := ks.pivyk.GenerateKey(piv.DefaultManagementKey, pivSlot, pivKeyOpts)
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}

		ykKp := YkKeyPair{
			keySore:      nil,
			slot:         int(pivSlot.Key),
			pubKey:       pubKey,
			id:           "",
			keyAlgorithm: opts.Algorithm,
			label:        "",
			keyUsage:     nil,
		}
		if ykKp.id, err = keystores.IdFromPublicKey(pubKey); err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		return &ykKp, nil
		//	} else if opts.Algorithm.ECCCurve != nil {
		//	} else if keystores.KeyAlgEd25519.Equal(opts.Algorithm) {
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm: %s", opts.Algorithm))
	}
}

func (ks *YkKeyStore) ImportKeyPair(der []byte) (kp keystores.KeyPair, err error) {
	panic("implement me")
}
