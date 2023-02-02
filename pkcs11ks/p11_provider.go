package pkcs11ks

import (
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11Config struct {
	DriverPath string
}

type Pkcs11Provider struct {
	// TODO: support multiple driver paths
	driverPath string
	// From Pkcs11 spec: CK_ULONG will sometimes be 32 bits, and sometimes perhaps 64 bits)
	ckULONGis32bit bool
	pkcs11Ctx      *p11api.Ctx
}

// Check whether implements the keystores.Provider interface
var _ keystores.Provider = &Pkcs11Provider{}

func NewPkcs11Provider(config Pkcs11Config) *Pkcs11Provider {
	p := Pkcs11Provider{
		driverPath:     config.DriverPath,
		ckULONGis32bit: false,
	}
	return &p
}

func (p *Pkcs11Provider) Open() error {
	if p.pkcs11Ctx != nil {
		return keystores.ErrorHandler(keystores.ErrAlreadyOpen, p)
	}
	p11Ctx := p11api.New(p.driverPath)
	if p11Ctx == nil {
		return keystores.ErrorHandler(fmt.Errorf("can't open driver: %s", p.driverPath), p)
	}
	err := p11Ctx.Initialize()
	if err != nil {
		return keystores.ErrorHandler(err, p)
	}
	p.pkcs11Ctx = p11Ctx
	return nil
}

func (p *Pkcs11Provider) Close() error {
	if p.pkcs11Ctx == nil {
		return keystores.ErrorHandler(keystores.ErrAlreadyClosed, p)
	}
	err := p.pkcs11Ctx.Finalize()
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	p.pkcs11Ctx = nil
	return nil
}

func (p *Pkcs11Provider) IsOpen() bool {
	return p.pkcs11Ctx != nil
}

func (p *Pkcs11Provider) KeyStores() ([]keystores.KeyStore, error) {
	if p.pkcs11Ctx == nil {
		if err := p.Open(); err != nil {
			return nil, keystores.ErrorHandler(err, p)
		}
	}

	slotIds, err := p.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return nil, keystores.ErrorHandler(err, p)
	}

	ksList := make([]keystores.KeyStore, 0)
	for _, slotId := range slotIds {
		ti, err1 := p.pkcs11Ctx.GetTokenInfo(slotId)
		if err1 != nil {
			continue
		}
		si, err1 := p.pkcs11Ctx.GetSlotInfo(slotId)
		if err1 != nil {
			err = utils.CollectError(err, keystores.ErrorHandler(err1, p))
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

	return ksList, err
}

func (p *Pkcs11Provider) FindKeyStore(tokenLabel string, tokenSerial string) (*Pkcs11KeyStore, error) {
	if p.pkcs11Ctx == nil {
		if err := p.Open(); err != nil {
			return nil, keystores.ErrorHandler(err, p)
		}
	}
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
