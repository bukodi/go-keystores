package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/pkcs11ks"
)

// Example:
// etokentest -PIN Passw0rd -driver /usr/lib/libeTPkcs11.so -serial 0255dfff

func main() {

	pDriver := flag.String("driver", "", "full path of the PKCS#11 driver lib")
	pSerial := flag.String("serial", "", "hex serial of the test eToken device. Example: 0255df11")
	pPIN := flag.String("PIN", "", "user PIN of the eToken")

	flag.Parse()

	if *pDriver == "" || *pSerial == "" || *pPIN == "" {
		flag.Usage()
		return
	}

	p := pkcs11ks.NewPkcs11Provider(pkcs11ks.Pkcs11Config{*pDriver})
	p.PINAuthenticator = func(ksDesc string, keyDesc string, isSO bool) (string, error) {
		return *pPIN, nil
	}

	ks, err := p.FindKeyStore("", *pSerial)
	if err != nil {
		fmt.Printf("FATAL: Can't open eToken. %+v\n", err)
		return
	}

	fmt.Printf("INFO : Token found. (name:%s, serial:%s)\n", ks.Name(), ks.Id())

	keyLabel := "ECP256 Test Key"
	genOpts := keystores.GenKeyPairOpts{
		Algorithm: keystores.KeyAlgECP256,
		Label:     keyLabel,
		KeyUsage: map[keystores.KeyUsage]bool{
			//keystores.KeyUsageAgree: true,
			keystores.KeyUsageDerive: true,
		},
		Exportable: false,
		Ephemeral:  false,
	}

	var kp keystores.KeyPair
	if kp, err = ks.CreateKeyPair(genOpts); err != nil {
		fmt.Printf("FATAL: Can't create key pair. %+v\n", err)
		return
	} else {
		fmt.Printf("INFO : Key pair generated. (Label:%s)\n", kp.Label())
	}

	defer func() {
		if err := kp.Destroy(); err != nil {
			fmt.Printf("FATAL: Key pair destroy failed. %+v\n", err)
			return
		} else {
			fmt.Printf("INFO : %s key pair destroyed\n", kp.Label())
		}
	}()

	pub := kp.Public()
	ecdsaPub, _ := pub.(*ecdsa.PublicKey)

	remotePriv, err := ecdsa.GenerateKey(ecdsaPub.Curve, rand.Reader)
	if err != nil {
		fmt.Printf("FATAL: remote key generation failed: %#v\n", err)
		return
	} else {
		fmt.Printf("INFO : remote test key pair generated\n")
	}

	sharedSecret1, err := kp.ECDH(&remotePriv.PublicKey)
	if err != nil {
		fmt.Printf("FATAL: ecdh first phase failed: %#v\n", err)
		return
	} else {
		fmt.Printf("INFO : ECDH( eToken.private, remote.public) = %v\n", sharedSecret1)
	}
	remoteEcdh, err := remotePriv.ECDH()
	if err != nil {
		fmt.Printf("FATAL: get ecdh from ecdsa failed: %#v\n", err)
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		fmt.Printf("FATAL: get ecdh from ecdsa failed: %#v\n", err)
		return
	}
	sharedSecret2, err := remoteEcdh.ECDH(ecdhPub)
	if err != nil {
		fmt.Printf("FATAL: ecdh second phase failed: %#v\n", err)
		return
	} else {
		fmt.Printf("INFO : ECDH( eToken.public, remote.private) = %v\n", sharedSecret2)
	}

	fmt.Println("-----------------")
	if bytes.Equal(sharedSecret1, sharedSecret2) {
		fmt.Printf("ECDH key agreement successfully tested.\n")
	} else {
		fmt.Printf("ECDH key agreement failed: the two shared secrects differs\n")
		return
	}
	fmt.Println("-----------------")
}
