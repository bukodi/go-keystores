package pkcs11ks

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/bukodi/go-keystores"
	"github.com/bukodi/go-keystores/utils"
	p11api "github.com/miekg/pkcs11"
)

type Pkcs11KeyStore struct {
	provider  *Pkcs11Provider
	slotId    uint
	tokenInfo *p11api.TokenInfo
	slotInfo  *p11api.SlotInfo

	knownRSAPubKeys          []*RSAPublicKeyAttributes
	knownRSAPrivKeys         []*RSAPrivateKeyAttributes
	knownECCPubKeys          []*ECCPublicKeyAttributes
	knownECCPrivKeys         []*ECCPrivateKeyAttributes
	knownOtherStorageObjects []*CommonStorageObjectAttributes
}

// Check whether implements the keystores.KeyStore interface
var _ keystores.KeyStore = &Pkcs11KeyStore{}

func (ks *Pkcs11KeyStore) Id() string {
	return ks.tokenInfo.SerialNumber
}

func (ks *Pkcs11KeyStore) Name() string {
	return ks.tokenInfo.Label
}

func (ks *Pkcs11KeyStore) Open() error {
	return keystores.ErrorHandler(fmt.Errorf("deprecated, don't use this"))
}

func (ks *Pkcs11KeyStore) Reload() error {
	sess, err := ks.aquireSession()
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)

	err = ks.readStorageObjects(sess)
	if err != nil {
		return keystores.ErrorHandler(err)
	}
	return err
}

func (ks *Pkcs11KeyStore) Close() error {
	return keystores.ErrorHandler(fmt.Errorf("deprecated, don't use this"))
}

func (ks *Pkcs11KeyStore) IsOpen() bool {
	return false
}

func (ks *Pkcs11KeyStore) SupportedPrivateKeyAlgorithms() []keystores.KeyAlgorithm {
	algs := []keystores.KeyAlgorithm{
		keystores.KeyAlgRSA1024,
		keystores.KeyAlgRSA2048,
		keystores.KeyAlgRSA3072,
		keystores.KeyAlgRSA4096,
		keystores.KeyAlgECP224,
		keystores.KeyAlgECP256,
		keystores.KeyAlgECP384,
		keystores.KeyAlgECP521,
	}
	return algs
}

func (ks *Pkcs11KeyStore) KeyPairById(id keystores.KeyPairId) keystores.KeyPair {
	kps, err := ks.KeyPairs(false)
	if err == nil {
		kp := kps[id]
		if kp != nil {
			return kp
		}
	}
	// TODO: implement single search
	return nil
}

func (ks *Pkcs11KeyStore) KeyPairs(reload bool) (keyPairs map[keystores.KeyPairId]keystores.KeyPair, retErr error) {
	if (ks.knownRSAPrivKeys == nil) && (ks.knownECCPrivKeys == nil) || reload {
		err := ks.Reload()
		if err != nil {
			return nil, keystores.ErrorHandler(err)
		}
	}

	keyPairs = make(map[keystores.KeyPairId]keystores.KeyPair)
	for _, privKeyAttrs := range ks.knownRSAPrivKeys {
		// Find matching pub key
		privIdBytes := privKeyAttrs.CKA_ID
		var pubKeyAttrs *RSAPublicKeyAttributes
		for _, p11RSAPubKey := range ks.knownRSAPubKeys {
			pubIdBytes := p11RSAPubKey.CommonKeyAttributes.CKA_ID
			if bytes.Equal(privIdBytes, pubIdBytes) {
				pubKeyAttrs = p11RSAPubKey
			}
		}
		// Create then KeyPair object
		if kp, err := ks.newRSAKeyPair(privKeyAttrs, pubKeyAttrs); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
		} else {
			keyPairs[kp.Id()] = kp
		}
	}
	for _, privKeyAttrs := range ks.knownECCPrivKeys {
		// Find matching pub key
		privIdBytes := privKeyAttrs.CKA_ID
		var pubKeyAttrs *ECCPublicKeyAttributes
		for _, pubKeyObj := range ks.knownECCPubKeys {
			pubIdBytes := pubKeyObj.CommonKeyAttributes.CKA_ID
			if bytes.Equal(privIdBytes, pubIdBytes) {
				pubKeyAttrs = pubKeyObj
			}
		}
		// Create then KeyPair object
		if kp, err := ks.newECCKeyPair(privKeyAttrs, pubKeyAttrs); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
		} else {
			keyPairs[kp.Id()] = kp
		}
	}
	return keyPairs, retErr
}

func (ks *Pkcs11KeyStore) CreateKeyPair(opts keystores.GenKeyPairOpts) (keystores.KeyPair, error) {
	sess, err := ks.aquireSession()
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)

	tokenPersistent := !opts.Ephemeral
	publicKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PUBLIC_KEY),
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_VERIFY, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageSign]))),
		p11api.NewAttribute(p11api.CKA_ENCRYPT, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDecrypt]))),
		p11api.NewAttribute(p11api.CKA_WRAP, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageUnwrap]))),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
	}
	privateKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PRIVATE_KEY),
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_SIGN, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageSign]))),
		p11api.NewAttribute(p11api.CKA_DECRYPT, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDecrypt]))),
		p11api.NewAttribute(p11api.CKA_UNWRAP, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageUnwrap]))),
		p11api.NewAttribute(p11api.CKA_DERIVE, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDerive]))),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
		p11api.NewAttribute(p11api.CKA_SENSITIVE, !opts.Exportable),
		p11api.NewAttribute(p11api.CKA_EXTRACTABLE, opts.Exportable),
	}

	if opts.Algorithm.RSAKeyLength > 0 {
		kp, err := ks.createRSAKeyPair(sess, opts, privateKeyTemplate, publicKeyTemplate)
		return kp, keystores.ErrorHandler(err, ks)
	} else if opts.Algorithm.ECCCurve != nil {
		kp, err := ks.createECCKeyPair(sess, opts, privateKeyTemplate, publicKeyTemplate)
		return kp, keystores.ErrorHandler(err, ks)
	} else {
		return nil, keystores.ErrorHandler(keystores.ErrOperationNotSupportedByProvider, ks)
	}
}

func (ks *Pkcs11KeyStore) ImportKeyPair(key crypto.PrivateKey, opts keystores.GenKeyPairOpts) (kp keystores.KeyPair, err error) {
	sess, err := ks.aquireSession()
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	defer sess.keyStore.releaseSession(sess)

	// Generate ID
	// TODO: implement opts.CKA_ID to caller provided CKA_ID
	pubKey, err := keystores.PublicKeyFromPrivate(key)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	kpId, err := keystores.IdFromPublicKey(pubKey)
	if err != nil {
		return nil, keystores.ErrorHandler(err)
	}
	ckaId, err := hex.DecodeString(string(kpId))
	if err == nil && len(ckaId) >= 8 {
		ckaId = ckaId[0:8]
	} else {
		ckaId = make([]byte, 8)
		rand.Read(ckaId)
	}

	tokenPersistent := !opts.Ephemeral
	publicKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PUBLIC_KEY),
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_VERIFY, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageSign]))),
		p11api.NewAttribute(p11api.CKA_ENCRYPT, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDecrypt]))),
		p11api.NewAttribute(p11api.CKA_WRAP, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageUnwrap]))),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
		p11api.NewAttribute(p11api.CKA_ID, ckaId),
	}
	privateKeyTemplate := []*p11api.Attribute{
		p11api.NewAttribute(p11api.CKA_CLASS, p11api.CKO_PRIVATE_KEY),
		p11api.NewAttribute(p11api.CKA_MODIFIABLE, true),
		p11api.NewAttribute(p11api.CKA_TOKEN, tokenPersistent),
		p11api.NewAttribute(p11api.CKA_SIGN, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageSign]))),
		p11api.NewAttribute(p11api.CKA_DECRYPT, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDecrypt]))),
		p11api.NewAttribute(p11api.CKA_UNWRAP, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageUnwrap]))),
		p11api.NewAttribute(p11api.CKA_DERIVE, bytesFrom_CK_BBOOL(CK_BBOOL(opts.KeyUsage[keystores.KeyUsageDerive]))),
		p11api.NewAttribute(p11api.CKA_LABEL, opts.Label),
		//p11api.NewAttribute(p11api.CKA_SENSITIVE, false),
		//p11api.NewAttribute(p11api.CKA_EXTRACTABLE, true),
		p11api.NewAttribute(p11api.CKA_ID, ckaId),
		p11api.NewAttribute(p11api.CKA_PRIVATE, true),
	}

	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		kp, err := ks.importRSAKeyPair(sess, rsaKey, opts, privateKeyTemplate, publicKeyTemplate)
		return kp, keystores.ErrorHandler(err, ks)
	} else if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		_ = ecKey
		return nil, keystores.ErrorHandler(keystores.ErrNotImplemented, ks)
	} else if edKey, ok := key.(ed25519.PrivateKey); ok {
		_ = edKey
		return nil, keystores.ErrorHandler(keystores.ErrNotImplemented, ks)
	} else {
		return nil, keystores.ErrorHandler(fmt.Errorf("unsupported algorithm"))
	}
}

func (ks *Pkcs11KeyStore) destroyObject(sess *Pkcs11Session, class CK_OBJECT_CLASS, id CK_Bytes, label CK_String) (objDeleted int, retErr error) {
	// Query all object handle
	attrs := make([]*p11api.Attribute, 0)
	if class != 0 {
		attrs = append(attrs, &p11api.Attribute{Type: p11api.CKA_CLASS, Value: bytesFrom_CK_OBJECT_CLASS(class, ks.provider.ckULONGis32bit)})
	}
	if id != nil {
		attrs = append(attrs, &p11api.Attribute{Type: p11api.CKA_ID, Value: bytesFrom_CK_Bytes(id)})
	}
	if label != "" {
		attrs = append(attrs, &p11api.Attribute{Type: p11api.CKA_LABEL, Value: bytesFrom_CK_String(label)})
	}

	if err := sess.ctx.FindObjectsInit(sess.hSession, attrs); err != nil {
		return 0, keystores.ErrorHandler(err)
	}
	defer func() {
		err := sess.ctx.FindObjectsFinal(sess.hSession)
		retErr = utils.CollectError(retErr, keystores.ErrorHandler(err))
	}()

	// Delete objects
	hObjs, _, err := sess.ctx.FindObjects(sess.hSession, 100)
	if err != nil {
		return 0, keystores.ErrorHandler(err)
	}
	for _, hObj := range hObjs {
		if err := sess.ctx.DestroyObject(sess.hSession, hObj); err != nil {
			retErr = utils.CollectError(retErr, keystores.ErrorHandler(err, ks))
		} else {
			objDeleted++
		}
	}
	return objDeleted, retErr
}
