package inmemoryks

import (
	"github.com/bukodi/go-keystores"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"log"
	"os"
)

func (imks *InMemoryKeyStore) SaveAsJKS(filename string, password []byte) error {
	ks := jks.New()
	kps, errs := imks.KeyPairs()
	for _, kp := range kps {

	}
	_ = ks

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
}
