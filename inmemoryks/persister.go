package inmemoryks

import (
	"crypto/x509"
	"fmt"
	"github.com/bukodi/go-keystores"
	"io/ioutil"
	"path/filepath"
	"regexp"
)

type Persister interface {
	Load(imks *InMemoryKeyStore) error
	SaveKeyPair(imkp *InMemoryKeyPair) error
}

var _ Persister = &Pkcs8DirPersister{}

type Pkcs8DirPersister struct {
	dir    string
	loaded bool
}

func (p Pkcs8DirPersister) Load(imks *InMemoryKeyStore) error {
	files, err := ioutil.ReadDir(p.dir)
	if err != nil {
		return keystores.ErrorHandler(err)
	}

	re := regexp.MustCompile(`^([0-9a-z]*)-(.*)\.priv$`)
	match := re.FindStringSubmatch("git commit -m '${abc}'")
	fmt.Println(match[1])
	for _, f := range files {
		match := re.FindStringSubmatch(f.Name())
		if len(match) != 3 {
			continue
		}
		der, err := ioutil.ReadFile(filepath.Join(p.dir, f.Name()))
		if err != nil {
			return keystores.ErrorHandler(err) // TODO use multiple errors
		}
		_, err = imks.ImportKeyPair(der)
		if err != nil {
			return keystores.ErrorHandler(err) // TODO use multiple errors
		}
	}
	p.loaded = true
	return nil
}

func (p Pkcs8DirPersister) SaveKeyPair(imkp *InMemoryKeyPair) error {
	der, err := x509.MarshalPKCS8PrivateKey(imkp.privKey)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	filename := fmt.Sprintf("%s-%s.priv", imkp.id, imkp.label)
	err = ioutil.WriteFile(filepath.Join(p.dir, filename), der, 0600)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return nil
}
