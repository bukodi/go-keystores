package keystores

import "encoding/asn1"

type KeyAlgorithm struct {
	Oid       asn1.ObjectIdentifier
	KeyLength int
	Name      string
}

var KeyAlgRSA2048 = KeyAlgorithm{
	Oid:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
	KeyLength: 2048,
	Name:      "RSA-2048",
}
var KeyAlgECP256 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	Name: "NIST P-256",
}
var KeyAlgEd25519 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 3, 101, 112},
	Name: "Ed25519",
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
