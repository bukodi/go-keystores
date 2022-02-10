package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/bukodi/go-keystores"
)

func IdFromPublicKey(pubKey crypto.PublicKey) (keystores.KeyPairId, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", keystores.ErrorHandler(err)
	}
	sum := sha256.Sum256(bytes)
	return keystores.KeyPairId(hex.EncodeToString(sum[:])), nil
}

func AlgorithmFromPublicKey(pubKey crypto.PublicKey) (keystores.KeyAlgorithm, error) {
	if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
		return keystores.KeyAlgRSA(rsaKey.Size()), nil
	} else if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
		if curvesAreEqual(elliptic.P256(), ecKey.Curve) {
			return keystores.KeyAlgECP256, nil
		} else if curvesAreEqual(elliptic.P224(), ecKey.Curve) {
			return keystores.KeyAlgECP224, nil
		} else if curvesAreEqual(elliptic.P384(), ecKey.Curve) {
			return keystores.KeyAlgECP384, nil
		} else if curvesAreEqual(elliptic.P521(), ecKey.Curve) {
			return keystores.KeyAlgECP521, nil
		} else {
			return keystores.KeyAlgorithm{}, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm"))
		}
	} else if _, ok := pubKey.(ed25519.PublicKey); ok {
		return keystores.KeyAlgEd25519, nil
	} else {
		return keystores.KeyAlgorithm{}, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm"))
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
