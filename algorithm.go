package keystores

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
)

type KeyAlgorithm struct {
	Oid          asn1.ObjectIdentifier
	RSAKeyLength int
	ECCCurve     elliptic.Curve
	Name         string
}

var KeyAlgRSA1024 = KeyAlgRSA(1024)
var KeyAlgRSA2048 = KeyAlgRSA(2048)
var KeyAlgRSA3072 = KeyAlgRSA(3072)
var KeyAlgRSA4096 = KeyAlgRSA(4096)

func KeyAlgRSA(keyLength int) KeyAlgorithm {
	return KeyAlgorithm{
		Oid:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
		RSAKeyLength: keyLength,
		Name:         fmt.Sprintf("RSA-%d", keyLength),
	}
}

var KeyAlgECP256 = KeyAlgorithm{
	Oid:      asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	ECCCurve: elliptic.P256(),
	Name:     "NIST P-256",
}

var KeyAlgECP224 = KeyAlgorithm{
	Oid:      asn1.ObjectIdentifier{1, 3, 132, 0, 33},
	ECCCurve: elliptic.P224(),
	Name:     "NIST P-224",
}

var KeyAlgECP384 = KeyAlgorithm{
	Oid:      asn1.ObjectIdentifier{1, 3, 132, 0, 34},
	ECCCurve: elliptic.P384(),
	Name:     "NIST P-384",
}

var KeyAlgECP521 = KeyAlgorithm{
	Oid:      asn1.ObjectIdentifier{1, 3, 132, 0, 35},
	ECCCurve: elliptic.P521(),
	Name:     "NIST P-521",
}

var KeyAlgEd25519 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 3, 101, 112},
	Name: "Ed25519",
}

var KeyAlgEd448 = KeyAlgorithm{
	Oid:  asn1.ObjectIdentifier{1, 3, 101, 113},
	Name: "Ed448",
}

var ECCAlgorithmByOid = make(map[string]*KeyAlgorithm)

func init() {
	ECCAlgorithmByOid[KeyAlgECP256.Oid.String()] = &KeyAlgECP256
	ECCAlgorithmByOid[KeyAlgECP224.Oid.String()] = &KeyAlgECP224
	ECCAlgorithmByOid[KeyAlgECP384.Oid.String()] = &KeyAlgECP384
	ECCAlgorithmByOid[KeyAlgECP521.Oid.String()] = &KeyAlgECP521
	ECCAlgorithmByOid[KeyAlgEd25519.Oid.String()] = &KeyAlgEd25519
	ECCAlgorithmByOid[KeyAlgEd448.Oid.String()] = &KeyAlgEd448
}

func (ka KeyAlgorithm) Equal(other KeyAlgorithm) bool {
	if !ka.Oid.Equal(other.Oid) {
		return false
	}
	if ka.RSAKeyLength != other.RSAKeyLength {
		return false
	}
	return true
}

func (ka KeyAlgorithm) String() string {
	return ka.Name
}

func AlgorithmFromPublicKey(pubKey crypto.PublicKey) (KeyAlgorithm, error) {
	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		return KeyAlgRSA(rsaKey.Size()), nil
	} else if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
		if curvesAreEqual(elliptic.P256(), ecKey.Curve) {
			return KeyAlgECP256, nil
		} else if curvesAreEqual(elliptic.P224(), ecKey.Curve) {
			return KeyAlgECP224, nil
		} else if curvesAreEqual(elliptic.P384(), ecKey.Curve) {
			return KeyAlgECP384, nil
		} else if curvesAreEqual(elliptic.P521(), ecKey.Curve) {
			return KeyAlgECP521, nil
		} else {
			return KeyAlgorithm{}, ErrorHandler(fmt.Errorf("unsupported algorithm"))
		}
	} else if _, ok := pubKey.(ed25519.PublicKey); ok {
		return KeyAlgEd25519, nil
	} else {
		return KeyAlgorithm{}, ErrorHandler(fmt.Errorf("unsupported algorithm"))
	}
}

func curvesAreEqual(ec1, ec2 elliptic.Curve) bool {
	cp1, cp2 := ec1.Params(), ec2.Params()
	return cp1.P.Cmp(cp2.P) == 0 && // the order of the underlying field
		cp1.N.Cmp(cp2.N) == 0 && // the order of the base point
		cp1.B.Cmp(cp2.B) == 0 && // the constant of the curve equation
		cp1.Gx.Cmp(cp2.Gx) == 0 && // x of the base point
		cp1.Gy.Cmp(cp2.Gy) == 0 && // y of the base point
		cp1.BitSize == cp2.BitSize // the size of the underlying field
}
