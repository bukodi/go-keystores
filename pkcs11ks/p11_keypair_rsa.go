package pkcs11ks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"io"
	"math/big"
)

// newRSAKeyPair creates a new Pkcs11KeyPair instance from the existing PKCS11 objects
func (ks *Pkcs11KeyStore) newRSAKeyPair(privKeyObject *RSAPrivateKeyAttributes, pubKeyObject *RSAPublicKeyAttributes) (*Pkcs11KeyPair, error) {
	kp := Pkcs11KeyPair{
		keyStore:        ks,
		rsaPrivKeyAttrs: privKeyObject,
		rsaPubKeyAttrs:  pubKeyObject,
	}

	kp.rsaPublicKey = &rsa.PublicKey{}
	kp.rsaPublicKey.N = kp.rsaPrivKeyAttrs.CKA_MODULUS
	kp.rsaPublicKey.E = int((*big.Int)(kp.rsaPrivKeyAttrs.CKA_PUBLIC_EXPONENT).Int64())

	kp.keyAlgorithm = keystores.KeyAlgRSA(kp.rsaPublicKey.Size() * 8)

	id, err := keystores.GenerateKeyPairIdFromPubKey(kp.rsaPublicKey)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.id = id

	return &kp, nil
}

// createRSAKeyPair creates a new RSA key pair on the underlying PKCS11 keystore
func (ks *Pkcs11KeyStore) createRSAKeyPair(sess *Pkcs11Session, opts keystores.GenKeyPairOpts, privateKeyTemplate []*p11api.Attribute, publicKeyTemplate []*p11api.Attribute) (*Pkcs11KeyPair, error) {
	publicKeyTemplate = append(publicKeyTemplate,
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11api.NewAttribute(p11api.CKA_MODULUS_BITS, opts.Algorithm.RSAKeyLength),
	)

	mechs := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}

	hPub, hPriv, err := sess.ctx.GenerateKeyPair(sess.hSession,
		mechs,
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var privKeyAttrs RSAPrivateKeyAttributes
	var pubKeyAttrs RSAPublicKeyAttributes
	if err := getP11Attributes(sess, hPriv, &privKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if err := getP11Attributes(sess, hPub, &pubKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp, err := ks.newRSAKeyPair(&privKeyAttrs, &pubKeyAttrs)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	// Generate ID
	var ckaId []byte
	if ckaId, err = hex.DecodeString(string(kp.Id())); err == nil && len(ckaId) >= 8 {
		ckaId = ckaId[0:8]
	} else {
		ckaId = make([]byte, 8)
		rand.Read(ckaId)
	}
	// Set attribute CKA_ID both on private and public key
	if err = sess.ctx.SetAttributeValue(sess.hSession, hPriv,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.rsaPrivKeyAttrs.CKA_ID = ckaId
	if err = sess.ctx.SetAttributeValue(sess.hSession, hPub,
		[]*p11api.Attribute{p11api.NewAttribute(p11api.CKA_ID, ckaId)}); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kp.rsaPubKeyAttrs.CKA_ID = ckaId

	return kp, nil
}

// createRSAKeyPair creates a new RSA key pair on the underlying PKCS11 keystore
func (ks *Pkcs11KeyStore) importRSAKeyPair(sess *Pkcs11Session, rsaPrivKey *rsa.PrivateKey, opts keystores.GenKeyPairOpts, privateKeyTemplate []*p11api.Attribute, publicKeyTemplate []*p11api.Attribute) (*Pkcs11KeyPair, error) {
	// check ops.Algorithm patches with rsaPrivKey
	if len(opts.Algorithm.Oid) > 0 {
		if (!opts.Algorithm.Oid.Equal(keystores.KeyAlgRSA1024.Oid)) ||
			opts.Algorithm.RSAKeyLength != rsaPrivKey.Size()*8 {
			return nil, keystores.ErrorHandler(fmt.Errorf("opts.Algorithm (%v) does not match with provided privateKey", opts.Algorithm))
		}
	}

	publicKeyTemplate = append(publicKeyTemplate,
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaPrivKey.PublicKey.E)).Bytes()),
		p11api.NewAttribute(p11api.CKA_MODULUS, rsaPrivKey.PublicKey.N.Bytes()),
	)

	privateKeyTemplate = append(privateKeyTemplate,
		//p11api.NewAttribute(p11api.CKA_MODULUS_BITS, opts.Algorithm.RSAKeyLength),
		p11api.NewAttribute(p11api.CKA_KEY_TYPE, p11api.CKK_RSA),
		p11api.NewAttribute(p11api.CKA_MODULUS, rsaPrivKey.PublicKey.N.Bytes()),
		p11api.NewAttribute(p11api.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaPrivKey.PublicKey.E)).Bytes()),
		p11api.NewAttribute(p11api.CKA_PRIVATE_EXPONENT, big.NewInt(int64(rsaPrivKey.E)).Bytes()),
		p11api.NewAttribute(p11api.CKA_PRIME_1, new(big.Int).Set(rsaPrivKey.Primes[0]).Bytes()),
		p11api.NewAttribute(p11api.CKA_PRIME_2, new(big.Int).Set(rsaPrivKey.Primes[1]).Bytes()),
		p11api.NewAttribute(p11api.CKA_EXPONENT_1, new(big.Int).Set(rsaPrivKey.Precomputed.Dp).Bytes()),
		p11api.NewAttribute(p11api.CKA_EXPONENT_2, new(big.Int).Set(rsaPrivKey.Precomputed.Dq).Bytes()),
		p11api.NewAttribute(p11api.CKA_COEFFICIENT, new(big.Int).Set(rsaPrivKey.Precomputed.Qinv).Bytes()),
	)

	hPriv, err := sess.ctx.CreateObject(sess.hSession, privateKeyTemplate)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	hPub, err := sess.ctx.CreateObject(sess.hSession, publicKeyTemplate)
	if err != nil {
		sess.ctx.DestroyObject(sess.hSession, hPriv)
		return nil, keystores.ErrorHandler(err)
	}

	var privKeyAttrs RSAPrivateKeyAttributes
	var pubKeyAttrs RSAPublicKeyAttributes
	if err := getP11Attributes(sess, hPriv, &privKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if err := getP11Attributes(sess, hPub, &pubKeyAttrs, ks.provider.ckULONGis32bit, true); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	kp, err := ks.newRSAKeyPair(&privKeyAttrs, &pubKeyAttrs)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	return kp, nil
}

// createRSAKeyPair creates a new RSA key pair on the underlying PKCS11 keystore
func (kp *Pkcs11KeyPair) exportRSAPrivateKey(sess *Pkcs11Session) (*rsa.PrivateKey, error) {
	hPrivKey, err := kp.privateKeyHandle(sess)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	var privKeyAttrs RSAPrivateKeyAttributes
	if err := getP11Attributes(sess, hPrivKey, &privKeyAttrs, kp.keyStore.provider.ckULONGis32bit, false); err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var goRsa rsa.PrivateKey
	goRsa.Primes = append(goRsa.Primes, privKeyAttrs.CKA_PRIME_1)
	if privKeyAttrs.CKA_PRIME_2 != nil {
		goRsa.Primes = append(goRsa.Primes, privKeyAttrs.CKA_PRIME_2)
	}
	goRsa.D = privKeyAttrs.CKA_PRIVATE_EXPONENT

	goRsa.PublicKey.N = privKeyAttrs.CKA_MODULUS
	goRsa.PublicKey.E = int(((*big.Int)(privKeyAttrs.CKA_PUBLIC_EXPONENT)).Int64())
	goRsa.Precompute()
	return &goRsa, nil
}

func hashToPSSParams(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint) {
	switch hashFunction {
	case crypto.SHA1:
		return p11api.CKM_SHA_1, p11api.CKG_MGF1_SHA1, 20
	case crypto.SHA224:
		return p11api.CKM_SHA224, p11api.CKG_MGF1_SHA224, 28
	case crypto.SHA256:
		return p11api.CKM_SHA256, p11api.CKG_MGF1_SHA256, 32
	case crypto.SHA384:
		return p11api.CKM_SHA384, p11api.CKG_MGF1_SHA384, 48
	case crypto.SHA512:
		return p11api.CKM_SHA512, p11api.CKG_MGF1_SHA512, 64
	default:
		return 0, 0, 0
	}
}
func (kp *Pkcs11KeyPair) rsaSign(sess *Pkcs11Session, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hPrivKey, err := kp.privateKeyHandle(sess)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}

	var hMech, mgf, hLen, sLen uint
	if hMech, mgf, hLen = hashToPSSParams(opts.HashFunc()); hLen == 0 {
		return nil, keystores.ErrorHandler(fmt.Errorf("hash not supported: %+v, %w", opts.HashFunc(), keystores.ErrOperationNotSupportedByProvider))
	}

	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		switch pssOpts.SaltLength {
		case rsa.PSSSaltLengthAuto:
			sLen = uint((kp.rsaPublicKey.N.BitLen()-1+7)/8 - 2 - int(hLen))
		case rsa.PSSSaltLengthEqualsHash:
			sLen = hLen
		default:
			sLen = uint(pssOpts.SaltLength)
		}
		params := p11api.NewPSSParams(hMech, mgf, sLen)
		mech := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS_PSS, params)}
		if err = sess.ctx.SignInit(sess.hSession, mech, hPrivKey); err != nil {
			return nil, err
		}
		if signature, err = sess.ctx.Sign(sess.hSession, digest); err != nil {
			return nil, keystores.ErrorHandler(err)
		} else {
			return signature, nil
		}
	} else {
		/* Calculate T for EMSA-PKCS1-v1_5. */
		oid := pkcs1Prefix[opts.HashFunc()]
		t := make([]byte, len(oid)+len(digest))
		copy(t[0:len(oid)], oid)
		copy(t[len(oid):], digest)
		mech := []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS, nil)}
		if err = sess.ctx.SignInit(sess.hSession, mech, hPrivKey); err != nil {
			return nil, keystores.ErrorHandler(err)
		}
		if signature, err = sess.ctx.Sign(sess.hSession, t); err != nil {
			return nil, keystores.ErrorHandler(err)
		} else {
			return signature, nil
		}
	}
}

func (kp *Pkcs11KeyPair) rsaDecrypt(sess *Pkcs11Session, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	hPrivKey, err := kp.privateKeyHandle(sess)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	var mech []*p11api.Mechanism
	if opts == nil {
		mech = []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS, nil)}
	} else if pkcsOpts, ok := opts.(*rsa.PKCS1v15DecryptOptions); ok {
		if pkcsOpts.SessionKeyLen != 0 {
			return nil, keystores.ErrorHandler(fmt.Errorf("unsupported RSA PKCS1v15 option"))
		}
		mech = []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS, nil)}
	} else if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		var hMech, mgf, hLen uint
		if hMech, mgf, hLen = hashToPSSParams(oaepOpts.Hash); hLen == 0 {
			return nil, keystores.ErrorHandler(fmt.Errorf("hash not supported: %+v, %w", oaepOpts.Hash, keystores.ErrOperationNotSupportedByProvider))
		}

		mechParams := p11api.NewOAEPParams(hMech, mgf, p11api.CKZ_DATA_SPECIFIED, oaepOpts.Label)
		//TODO: mechParams = p11api.NewOAEPParams(p11api.CKM_SHA3_256, p11api.CKG_MGF1_SHA256, p11api.CKZ_DATA_SPECIFIED, nil)
		mech = []*p11api.Mechanism{p11api.NewMechanism(p11api.CKM_RSA_PKCS_OAEP, mechParams)}
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported RSA option type: %T", opts))
	}

	if err := sess.ctx.DecryptInit(sess.hSession, mech, hPrivKey); err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	if plaintext, err := sess.ctx.Decrypt(sess.hSession, ciphertext); err != nil {
		return nil, keystores.ErrorHandler(err)
	} else {
		return plaintext, nil
	}
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}
