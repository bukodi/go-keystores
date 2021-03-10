package pkcs11ks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11Config struct {
	DriverPath string
}

type Pkcs11Provider struct {
	driverPath string
	pkcs11Ctx  *p11api.Ctx
}

// Check whether implements the keystores.Provider interface
var _ keystores.Provider = &Pkcs11Provider{}

func NewPkcs11Provider(config Pkcs11Config) *Pkcs11Provider {
	p := Pkcs11Provider{
		driverPath: config.DriverPath,
	}
	return &p
}

func (p *Pkcs11Provider) Open() error {
	if p.pkcs11Ctx != nil {
		return keystores.ErrorHandler(keystores.ErrKeyStoreAlreadyOpen, p)
	}
	p11Ctx := p11api.New(p.driverPath)
	err := p11Ctx.Initialize()
	if err != nil {
		return keystores.ErrorHandler(err, p)
	}
	p.pkcs11Ctx = p11Ctx
	return nil
}

func (p *Pkcs11Provider) Close() error {
	if p.pkcs11Ctx == nil {
		return keystores.ErrorHandler(keystores.ErrKeyStoreAlreadyClosed, p)
	}
	err := p.pkcs11Ctx.Finalize()
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return nil
}

func (p *Pkcs11Provider) KeyStores() ([]keystores.KeyStore, []error) {
	errors := make([]error, 0)
	slotIds, err := p.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return nil, []error{keystores.ErrorHandler(err, p)}
	}

	ksList := make([]keystores.KeyStore, 0)
	for _, slotId := range slotIds {
		ti, err := p.pkcs11Ctx.GetTokenInfo(slotId)
		if err != nil {
			errors = append(errors, keystores.ErrorHandler(err, p))
			continue
		}
		si, err := p.pkcs11Ctx.GetSlotInfo(slotId)
		if err != nil {
			errors = append(errors, keystores.ErrorHandler(err, p))
			continue
		}
		ks := Pkcs11KeyStore{
			provider:  p,
			slotId:    slotId,
			tokenInfo: &ti,
			slotInfo:  &si,
		}

		ksList = append(ksList, &ks)
	}

	if len(errors) == 0 {
		return ksList, nil
	} else {
		return ksList, errors
	}
}

func (p *Pkcs11Provider) FindKeyStore(tokenLabel string, tokenSerial string) (*Pkcs11KeyStore, error) {
	slotIds, err := p.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return nil, keystores.ErrorHandler(err, p)
	}

	var retErr error = nil
	var foundKs *Pkcs11KeyStore = nil
	for _, slotId := range slotIds {
		ti, err := p.pkcs11Ctx.GetTokenInfo(slotId)
		if err != nil {
			retErr = keystores.ErrorHandler(err, p, slotId)
			continue
		}
		if tokenLabel != "" && ti.Label != tokenLabel {
			continue
		}
		if tokenSerial != "" && ti.SerialNumber != tokenSerial {
			continue
		}
		si, err := p.pkcs11Ctx.GetSlotInfo(slotId)
		if err != nil {
			return nil, keystores.ErrorHandler(err, p, slotId)
		}

		ks := Pkcs11KeyStore{
			provider:  p,
			slotId:    slotId,
			tokenInfo: &ti,
			slotInfo:  &si,
		}

		if foundKs != nil {
			return nil, keystores.ErrorHandler(
				fmt.Errorf("more than one key store found with conditions: label=%q, serial=%q", tokenLabel, tokenSerial), p, slotId)
		}
		foundKs = &ks
	}
	if foundKs == nil {
		return nil, keystores.ErrorHandler(
			fmt.Errorf("key store not found with conditions: label=%q, serial=%q", tokenLabel, tokenSerial), p, retErr)
	}
	return foundKs, nil
}
