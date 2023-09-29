package yubiks

import (
	"errors"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/go-piv/piv-go/piv"
	"strings"
)

type YkProvider struct {
}

// Check whether implements the keystores.Provider interface
var _ keystores.Provider = &YkProvider{}

func NewYkProvider() *YkProvider {
	p := YkProvider{}
	return &p
}

func (p *YkProvider) Open() error {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	_ = cards
	return nil
}

func (p *YkProvider) Close() error {
	return nil
}

func (p *YkProvider) IsOpen() bool {
	return true
}

func (p *YkProvider) KeyStores() ([]keystores.KeyStore, error) {
	// List all smartcards connected to the system.
	cards, err := piv.Cards() // TODO: convert this function to return []error
	if err != nil {
		return nil, keystores.ErrorHandler(err, p)
	}

	// Find a YubiKey and open the reader.
	ksList := make([]keystores.KeyStore, 0)

	var retErr error
	for _, card := range cards {
		if !(strings.Contains(strings.ToLower(card), "yubikey") || strings.Contains(strings.ToLower(card), "yubikey")) {
			continue
		}
		pivYk, err := piv.Open(card)
		if err != nil {
			retErr = errors.Join(retErr, keystores.ErrorHandler(err, p))
			continue
		}
		serialInt, err := pivYk.Serial()
		if err != nil {
			retErr = errors.Join(retErr, keystores.ErrorHandler(err, p))
			continue
		}

		ks := YkKeyStore{
			provider: p,
			pivyk:    pivYk,
			serial:   fmt.Sprintf("%d", serialInt),
			cardName: card,
		}
		ksList = append(ksList, &ks)
	}

	return ksList, retErr
}

func (p *YkProvider) FindKeyStore(ykSerial string) (*YkKeyStore, error) {
	ksList, errs := p.KeyStores()
	var foundKs *YkKeyStore = nil
	for _, ks := range ksList {
		ykKs, ok := ks.(*YkKeyStore)
		if !ok {
			continue
		}
		if ykSerial != "" && ykKs.serial != ykSerial {
			continue
		}

		if foundKs != nil {
			return nil, keystores.ErrorHandler(
				fmt.Errorf("more than one key store found with conditions: serial=%q", ykSerial), p)
		}
		foundKs = ykKs
	}
	if foundKs == nil {
		return nil, keystores.ErrorHandler(
			fmt.Errorf("key store not found with conditions: serial=%q", ykSerial), p, errs)
	}
	return foundKs, nil
}
