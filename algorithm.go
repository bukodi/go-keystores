package keystores

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
)

type KeyAlgorithm struct {
	Oid         asn1.ObjectIdentifier
	KeyLength   int
	CurveParams *elliptic.CurveParams
	Name        string
}

var KeyAlgRSA1024 = KeyAlgRSA(1024)
var KeyAlgRSA2048 = KeyAlgRSA(2048)
var KeyAlgRSA3072 = KeyAlgRSA(3072)
var KeyAlgRSA4096 = KeyAlgRSA(4096)

func KeyAlgRSA(keyLength int) KeyAlgorithm {
	return KeyAlgorithm{
		Oid:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
		KeyLength: keyLength,
		Name:      fmt.Sprintf("RSA-%d", keyLength),
	}
}

var KeyAlgECP256 = KeyAlgorithm{
	Oid:         asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	CurveParams: elliptic.P256().Params(),
	Name:        "NIST P-256",
}

var KeyAlgECP224 = KeyAlgorithm{
	Oid:         asn1.ObjectIdentifier{1, 3, 132, 0, 33},
	CurveParams: elliptic.P224().Params(),
	Name:        "NIST P-224",
}

var KeyAlgECP384 = KeyAlgorithm{
	Oid:         asn1.ObjectIdentifier{1, 3, 132, 0, 34},
	CurveParams: elliptic.P384().Params(),
	Name:        "NIST P-384",
}

var KeyAlgECP521 = KeyAlgorithm{
	Oid:         asn1.ObjectIdentifier{1, 3, 132, 0, 35},
	CurveParams: elliptic.P521().Params(),
	Name:        "NIST P-521",
}

var KeyAlgEd25519 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 3, 101, 112},
	Name: "Ed25519",
}

var KeyAlgEd448 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 3, 101, 113},
	Name: "Ed448",
}

func (ka KeyAlgorithm) Equal(other KeyAlgorithm) bool {
	if !ka.Oid.Equal(other.Oid) {
		return false
	}
	if ka.KeyLength != other.KeyLength {
		return false
	}
	return true
}

func (ka KeyAlgorithm) String() string {
	return ka.Name
}
