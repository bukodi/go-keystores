package pkcs11ks

import (
	"context"
	"errors"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"path/filepath"
	"sync"
)

type ProviderConfig []DriverLibConfig

type DriverLibConfig struct {
	LibPath          string
	CkULONGis32bit   bool
	SlotNameMask     string
	ManufacturerMask string
	TokenLabelMask   string
	pkcs11Ctx        *p11api.Ctx
	pkcs11Provider   *Pkcs11Provider
	// TODO: add concurrency mode enum
}

type Pkcs11Provider struct {
	configLock       sync.RWMutex
	libConfigs       []DriverLibConfig
	knownKeyStores   []*Pkcs11KeyStore
	PINAuthenticator func(keystoreDesc string, keyDesc string, isSO bool) (string, error)
	AllowParallel    bool
}

// Check whether implements the keystores.Provider interface
var _ keystores.Provider = &Pkcs11Provider{}

func NewPkcs11Provider(config ProviderConfig) *Pkcs11Provider {
	p := Pkcs11Provider{
		libConfigs: config,
	}
	for i := range p.libConfigs {
		p.libConfigs[i].pkcs11Provider = &p
	}
	return &p
}

func filterMasks(driverCfg *DriverLibConfig, slotInfo *p11api.SlotInfo, tokenInfo *p11api.TokenInfo) error {
	if driverCfg.SlotNameMask != "" {
		if matches, _ := filepath.Match(driverCfg.SlotNameMask, slotInfo.SlotDescription); !matches {
			return fmt.Errorf("slot name (%s) does not match with pattern(%s)", slotInfo.SlotDescription, driverCfg.SlotNameMask)
		}
	}
	if driverCfg.TokenLabelMask != "" {
		if matches, _ := filepath.Match(driverCfg.TokenLabelMask, tokenInfo.Label); !matches {
			return fmt.Errorf("token label (%s) does not match with pattern(%s)", tokenInfo.Label, driverCfg.TokenLabelMask)
		}
	}

	// TODO: Implement more filters
	return nil
}

// Open opens the provider, and enumerates the available tokens
func (driverCfg *DriverLibConfig) listTokens(ctx context.Context, chKs chan<- *Pkcs11KeyStore, chErr chan<- error) {
	if driverCfg.pkcs11Ctx != nil {
		chErr <- keystores.ErrorHandler(keystores.ErrAlreadyOpen, driverCfg)
		return
	}

	driverCfg.pkcs11Ctx = p11api.New(driverCfg.LibPath)
	if driverCfg.pkcs11Ctx == nil {
		chErr <- fmt.Errorf("can't open driver: %s", driverCfg.LibPath)
		return
	} else {
		pkgSlog.Debug("Driver loaded", "libPath", driverCfg.LibPath)
	}

	if ctx.Err() != nil {
		chErr <- ctx.Err()
		return
	}

	err := driverCfg.pkcs11Ctx.Initialize()
	if err != nil {
		if errors.Is(err, p11api.Error(p11api.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			pkgSlog.Warn("Driver already initialized", "libPath", driverCfg.LibPath)
		} else {
			chErr <- fmt.Errorf("can't initialize driver (%s): %w", driverCfg.LibPath, err)
			return
		}
	} else {
		pkgSlog.Debug("Driver initialized", "libPath", driverCfg.LibPath)
	}

	if ctx.Err() != nil {
		chErr <- ctx.Err()
		return
	}

	slotIds, err := driverCfg.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		chErr <- fmt.Errorf("can't query slots (%s): %w", driverCfg.LibPath, err)
		return
	} else {
		pkgSlog.Debug("Slots queried", "libPath", driverCfg.LibPath, "slotIds", slotIds)
	}

	if ctx.Err() != nil {
		chErr <- ctx.Err()
		return
	}

	for _, slotId := range slotIds {
		si, err1 := driverCfg.pkcs11Ctx.GetSlotInfo(slotId)
		if err1 != nil {
			chErr <- fmt.Errorf("can't get slot info (%s, %d): %w", driverCfg.LibPath, slotId, err)
			continue
		}
		if ctx.Err() != nil {
			chErr <- ctx.Err()
			return
		}

		ti, err1 := driverCfg.pkcs11Ctx.GetTokenInfo(slotId)
		if err1 != nil {
			chErr <- fmt.Errorf("can't get token info (%s, %d): %w", driverCfg.LibPath, slotId, err)
			continue
		}
		if ctx.Err() != nil {
			chErr <- ctx.Err()
			return
		}

		if err := filterMasks(driverCfg, &si, &ti); err != nil {
			pkgSlog.Debug("Token skipped", "libPath", driverCfg.LibPath, "slotId", slotId, "tokenName", ti.Label, "err", err)
			continue
		}

		ks := Pkcs11KeyStore{
			driverConfig: driverCfg,
			slotId:       slotId,
			tokenInfo:    &ti,
			slotInfo:     &si,
		}
		chKs <- &ks
		pkgSlog.Info("Token found", "libPath", driverCfg.LibPath, "slotId", slotId, "tokenName", ti.Label)
	}
}

func (p *Pkcs11Provider) Open() error {
	var retErr error
	<-p.OpenAsync(context.Background(), func(ks keystores.KeyStore) {
		p.knownKeyStores = append(p.knownKeyStores, ks.(*Pkcs11KeyStore))
	}, func(err error) {
		retErr = errors.Join(retErr, err)
	})
	return retErr
}

// When the context is canceled, the ctx.Err() will be passed to onErr handler.
func (p *Pkcs11Provider) OpenAsync(ctx context.Context, onKs func(keystores.KeyStore), onErr func(error)) <-chan struct{} {
	chDone := make(chan struct{})
	chKs := make(chan *Pkcs11KeyStore)
	chErr := make(chan error)

	// Go routine to process key store and error channels and call the event handlers
	go func() {
		defer close(chDone)

		for {
			select {
			case <-ctx.Done():
				if onErr != nil {
					onErr(ctx.Err())
				}
				return
			case ks, ok := <-chKs:
				if !ok {
					return
				} else {
					if onKs != nil {
						onKs(ks)
					}
				}
			case err, ok := <-chErr:
				if !ok {
					return
				} else {
					if onErr != nil {
						onErr(err)
					}
				}
			}
		}
	}()

	// Start the token listing for every driver configuration
	go func() {
		var wg sync.WaitGroup
		for _, driverCfg := range p.libConfigs {
			if p.AllowParallel {
				wg.Add(1)
				go func() {
					defer wg.Done()
					driverCfg.listTokens(ctx, chKs, chErr)
				}()
			} else {
				driverCfg.listTokens(ctx, chKs, chErr)
			}
		}
		wg.Wait()
		close(chKs)
		close(chErr)
	}()

	return chDone
}

func (p *Pkcs11Provider) Close() (retErr error) {
	for _, ks := range p.knownKeyStores {
		if err := ks.Close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}
	p.knownKeyStores = nil
	for _, driverCfg := range p.libConfigs {
		if driverCfg.pkcs11Ctx != nil {
			if err := driverCfg.pkcs11Ctx.Finalize(); err != nil {
				retErr = errors.Join(retErr, err)
			}
			driverCfg.pkcs11Ctx = nil
		}
	}
	return retErr
}

func (p *Pkcs11Provider) IsOpen() bool {
	return p.knownKeyStores != nil
}

func (p *Pkcs11Provider) KeyStores() ([]keystores.KeyStore, error) {
	retKs := make([]keystores.KeyStore, 0, len(p.knownKeyStores))
	for _, ks := range p.knownKeyStores {
		retKs = append(retKs, ks)
	}
	return retKs, nil
}
