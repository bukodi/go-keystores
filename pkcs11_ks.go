package keystores

import (
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

type Pkcs11Provider struct {
	driverPath string
	pkcs11Ctx  *pkcs11.Ctx
	slotId     uint
	tokenInfo  *pkcs11.TokenInfo
	slotInfo   *pkcs11.SlotInfo
}

type Pkcs11KeyStore struct {
	driverPath string
	pkcs11Ctx  *pkcs11.Ctx
	slotId     uint
	tokenInfo  *pkcs11.TokenInfo
	slotInfo   *pkcs11.SlotInfo
}

func ListPkcs11KeyStores(driverPath string) ([]*Pkcs11KeyStore, error) {
	p11Ctx := pkcs11.New(driverPath)
	err := p11Ctx.Initialize()
	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Can't init Pkcs11 diver: %s", driverPath))
	}

	slotIds, err := p11Ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	ksList := make([]*Pkcs11KeyStore, 0)
	for _, slotId := range slotIds {
		ks := new(Pkcs11KeyStore)
		ks.driverPath = driverPath
		ks.pkcs11Ctx = p11Ctx

		ti, err := p11Ctx.GetTokenInfo(slotId)
		if err != nil {
			// TODO: Log error
			continue
		}
		ks.slotId = slotId
		si, err := p11Ctx.GetSlotInfo(slotId)
		if err != nil {
			return nil, err
		}
		ks.slotInfo = &si
		ks.tokenInfo = &ti
		ksList = append(ksList, ks)
	}

	return ksList, nil
}

func OpenPkcs11KeyStore(driverPath string, tokenLabel string, tokenSerial string) (*Pkcs11KeyStore, error) {
	p11Ctx := pkcs11.New(driverPath)
	err := p11Ctx.Initialize()
	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Can't init Pkcs11 diver: %s", driverPath))
	}

	slotIds, err := p11Ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	ks := new(Pkcs11KeyStore)
	ks.driverPath = driverPath
	ks.pkcs11Ctx = p11Ctx

	for _, slotId := range slotIds {
		ti, err := p11Ctx.GetTokenInfo(slotId)
		if err != nil {
			// TODO: Don't return when this call fails for a particular token. Collect the errors and return when token not found.
			return nil, err
		}
		if tokenLabel != "" && ti.Label != tokenLabel {
			continue
		}
		if tokenSerial != "" && ti.SerialNumber != tokenSerial {
			continue
		}
		ks.slotId = slotId
		si, err := p11Ctx.GetSlotInfo(slotId)
		if err != nil {
			return nil, err
		}
		ks.slotInfo = &si
		ks.tokenInfo = &ti
		break
	}
	if ks.tokenInfo == nil {
		return nil, errors.New("Token not found")
	}

	return ks, nil
}

func CreatePkcs11KeyStore(driverPath string, tokenLabel string, tokenSerial string) (*Pkcs11KeyStore, error) {
	p11Ctx := pkcs11.New(driverPath)
	err := p11Ctx.Initialize()
	if err != nil {
		return nil, errors.WithStack(errors.Wrapf(err, "Can't init Pkcs11 diver: %s", driverPath))
	}

	slotIds, err := p11Ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	ks := new(Pkcs11KeyStore)
	ks.driverPath = driverPath
	ks.pkcs11Ctx = p11Ctx

	for _, slotId := range slotIds {
		ti, err := p11Ctx.GetTokenInfo(slotId)
		if err != nil {
			// TODO: Don't return when this call fails for a particular token. Collect the errors and return when token not found.
			return nil, err
		}
		if tokenLabel != "" && ti.Label != tokenLabel {
			continue
		}
		if tokenSerial != "" && ti.SerialNumber != tokenSerial {
			continue
		}
		ks.slotId = slotId
		si, err := p11Ctx.GetSlotInfo(slotId)
		if err != nil {
			return nil, err
		}
		ks.slotInfo = &si
		ks.tokenInfo = &ti
		break
	}
	if ks.tokenInfo == nil {
		return nil, errors.New("Token not found")
	}

	return ks, nil
}

func (p Pkcs11KeyStore) SupportedPrivateKeyAlgorithms() []KeyAlgorithm {
	algs := []KeyAlgorithm{KeyAlgRSA2048, KeyAlgECP256}
	return algs
}

func (p Pkcs11KeyStore) KeyPairs() []KeyPair {
	panic("implement me")
}

func (p Pkcs11KeyStore) CreateKeyPair(privateKeyAlgorithm KeyAlgorithm, opts interface{}) (kp KeyPair, err error) {
	panic("implement me")
}

func (p Pkcs11KeyStore) ImportKeyPair(der []byte) (kp KeyPair, err error) {
	panic("implement me")
}
