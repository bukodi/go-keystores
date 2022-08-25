package pkcs11ks

import (
	"encoding/binary"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"reflect"
	"time"
)

const CKK_RSA = CK_KEY_TYPE(p11api.CKK_RSA)
const CKK_EC = CK_KEY_TYPE(p11api.CKK_EC)
const CKK_ECDSA = CK_KEY_TYPE(p11api.CKK_ECDSA)
const CKK_AES = CK_KEY_TYPE(p11api.CKK_AES)

type CK_BBOOL bool
type CK_ULONG uint32
type CK_DATE time.Time
type CK_KEY_TYPE CK_ULONG
type CK_Bytes []byte
type CK_BigInt CK_Bytes
type CK_String string
type CK_OBJECT_CLASS CK_ULONG
type CK_MECHANISM_TYPE CK_ULONG
type CK_MECHANISM_TYPE_PTR []CK_MECHANISM_TYPE
type CK_ATTRIBUTE_PTR CK_Bytes

func bytesTo_CK_BBOOL(bytes []byte) (CK_BBOOL, error) {
	if len(bytes) != 1 {
		return false, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 1, len(bytes))
	}
	return bytes[0] != 0, nil
}

func bytesFrom_CK_BBOOL(v CK_BBOOL) []byte {
	bytes := []byte{0}
	if v {
		bytes[0] = 1
	} else {
		bytes[0] = 0
	}
	return bytes
}

func bytesTo_CK_ULONG(bytes []byte) (CK_ULONG, error) {
	if len(bytes) != 4 {
		return 0, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 4, len(bytes))
	}
	return CK_ULONG(binary.LittleEndian.Uint32(bytes)), nil
}

func bytesFrom_CK_ULONG(a CK_ULONG) []byte {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes
}

func bytesTo_CK_DATE(bytes []byte) (CK_DATE, error) {
	if len(bytes) != 8 {
		return CK_DATE{}, keystores.ErrorHandler(fmt.Errorf("wrong attr value size. Expected %d, actual %d", 8, len(bytes)))
	}
	str := string(bytes)
	d, err := time.Parse("20060102", str)
	if err != nil {
		return CK_DATE{}, keystores.ErrorHandler(err)
	}
	return CK_DATE(d), nil
}

func bytesFrom_CK_DATE(a CK_DATE) []byte {
	str := time.Time(a).Format("20060102")
	return []byte(str)
}

func bytesTo_CK_KEY_TYPE(bytes []byte) (CK_KEY_TYPE, error) {
	switch len(bytes) {
	case 4:
		return CK_KEY_TYPE(binary.LittleEndian.Uint32(bytes)), nil
	case 8:
		return CK_KEY_TYPE(binary.LittleEndian.Uint64(bytes)), nil
	default:
		return 0, fmt.Errorf("wrong attr value size. Expected 4 or 8 , actual %d", len(bytes))
	}
}

func bytesFrom_CK_KEY_TYPE(a CK_KEY_TYPE) []byte {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes
}

func bytesTo_CK_Bytes(bytes []byte) (CK_Bytes, error) {
	x := make([]byte, len(bytes))
	for i, b := range bytes {
		(x)[i] = b
	}
	return x, nil
}

func bytesFrom_CK_Bytes(a CK_Bytes) []byte {
	bytes := make([]byte, len(a))
	for i, b := range a {
		bytes[i] = b
	}
	return bytes
}

func bytesTo_CK_ATTRIBUTE_PTR(bytes []byte) (CK_ATTRIBUTE_PTR, error) {
	x := make([]byte, len(bytes))
	for i, b := range bytes {
		(x)[i] = b
	}
	return x, nil
}

func bytesFrom_CK_ATTRIBUTE_PTR(a CK_ATTRIBUTE_PTR) []byte {
	bytes := make([]byte, len(a))
	for i, b := range a {
		bytes[i] = b
	}
	return bytes
}

func bytesTo_CK_String(bytes []byte) (CK_String, error) {
	buff := make([]byte, len(bytes))
	for i, b := range bytes {
		buff[i] = b
	}
	str := string(buff)
	return CK_String(str), nil
}

func bytesFrom_CK_String(a CK_String) []byte {
	aAsBytes := []byte(a)
	bytes := make([]byte, len(aAsBytes))
	for i, b := range aAsBytes {
		bytes[i] = b
	}
	return bytes
}

func bytesTo_CK_OBJECT_CLASS(bytes []byte) (CK_OBJECT_CLASS, error) {
	switch len(bytes) {
	case 4:
		return CK_OBJECT_CLASS(binary.LittleEndian.Uint32(bytes)), nil
	case 8:
		return CK_OBJECT_CLASS(binary.LittleEndian.Uint64(bytes)), nil
	default:
		return 0, fmt.Errorf("wrong attr value size. Expected 4 or 8 , actual %d", len(bytes))
	}
}

func bytesFrom_CK_OBJECT_CLASS(a CK_OBJECT_CLASS) []byte {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes
}
func bytesTo_CK_MECHANISM_TYPE(bytes []byte) (CK_MECHANISM_TYPE, error) {
	if len(bytes) != 4 {
		return 0, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 4, len(bytes))
	}
	return CK_MECHANISM_TYPE(binary.LittleEndian.Uint32(bytes)), nil
}

func bytesFrom_CK_MECHANISM_TYPE(a CK_MECHANISM_TYPE) []byte {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes
}

func bytesTo_CK_MECHANISM_TYPE_PTR(bytes []byte) (CK_MECHANISM_TYPE_PTR, error) {
	if len(bytes)%4 != 0 {
		return nil, fmt.Errorf("wrong attr value size. Expected mod 4 == 0, actual %d", len(bytes))
	}
	x := make([]CK_MECHANISM_TYPE, len(bytes)/4)
	for i := 0; i < len(bytes)/4; i += 1 {
		mt := CK_MECHANISM_TYPE(binary.LittleEndian.Uint32(bytes[i*4 : i*4+4]))
		(x)[i] = mt
	}
	return x, nil
}

func bytesFrom_CK_MECHANISM_TYPE_PTR(a CK_MECHANISM_TYPE_PTR) []byte {
	bytes := make([]byte, len(a)*4)
	for i := 0; i < len(a); i += 1 {
		mt := (a)[i]
		binary.LittleEndian.PutUint32(bytes[i*4:i*4+4], uint32(mt))
	}
	return bytes
}

func uint32or64ValueFromBytes(bytes []byte, v reflect.Value) error {
	switch len(bytes) {
	case 4:
		v.SetUint(uint64(binary.LittleEndian.Uint32(bytes)))
	case 8:
		v.SetUint(uint64(binary.LittleEndian.Uint64(bytes)))
	default:
		return fmt.Errorf("wrong attr value size (expected length 4 or 8 , actual is %d)", len(bytes))
	}
	return nil
}

func ckValueSetFromBytes(bytes []byte, v reflect.Value) error {
	switch v.Type() {
	case reflect.TypeOf(CK_BBOOL(false)):
		if len(bytes) != 1 {
			return fmt.Errorf("wrong attr value size. Expected %d, actual %d", 1, len(bytes))
		}

		v.SetBool(bytes[0] != 0)
		return nil
	case reflect.TypeOf(CK_ULONG(0)):
		return uint32or64ValueFromBytes(bytes, v)
	case reflect.TypeOf(CK_DATE{}):
		if len(bytes) == 0 {
			v.Set(reflect.ValueOf(CK_DATE{}))
			return nil
		}
		if len(bytes) != 8 {
			return keystores.ErrorHandler(fmt.Errorf("wrong attr value size. Expected %d, actual %d", 8, len(bytes)))
		}
		str := string(bytes)
		d, err := time.Parse("20060102", str)
		if err != nil {
			return keystores.ErrorHandler(err)
		}
		v.Set(reflect.ValueOf(CK_DATE(d)))
		return nil
	case reflect.TypeOf(CK_KEY_TYPE(0)):
		return uint32or64ValueFromBytes(bytes, v)
	case reflect.TypeOf(CK_Bytes{}), reflect.TypeOf(CK_BigInt{}):
		x := make([]byte, len(bytes))
		for i, b := range bytes {
			(x)[i] = b
		}
		v.SetBytes(x)
		return nil
	case reflect.TypeOf(CK_String("")):
		buff := make([]byte, len(bytes))
		for i, b := range bytes {
			buff[i] = b
		}
		v.SetString(string(buff))
		return nil
	case reflect.TypeOf(CK_OBJECT_CLASS(0)):
		return uint32or64ValueFromBytes(bytes, v)
	case reflect.TypeOf(CK_MECHANISM_TYPE(0)):
		return uint32or64ValueFromBytes(bytes, v)
		v.SetUint(uint64(binary.LittleEndian.Uint32(bytes)))
		return nil
	case reflect.TypeOf(CK_MECHANISM_TYPE_PTR{}):
		if len(bytes)%4 != 0 {
			return fmt.Errorf("wrong attr value size. Expected mod 4 == 0, actual %d", len(bytes))
		}
		x := make([]CK_MECHANISM_TYPE, len(bytes)/4)
		for i := 0; i < len(bytes)/4; i += 1 {
			mt := CK_MECHANISM_TYPE(binary.LittleEndian.Uint32(bytes[i*4 : i*4+4]))
			(x)[i] = mt
		}
		v.Set(reflect.ValueOf(x))
		return nil
	case reflect.TypeOf(CK_ATTRIBUTE_PTR{}):
		x := make([]byte, len(bytes))
		for i, b := range bytes {
			(x)[i] = b
		}
		v.SetBytes(x)
		return nil
	default:
		return fmt.Errorf("unsupported type: %s", v.Type().String())
	}
}

func ckValueWriteToBytes(v reflect.Value) ([]byte, error) {
	switch v.Type() {
	case reflect.TypeOf(CK_BBOOL(false)):
		bytes := []byte{0}
		if v.Bool() {
			bytes[0] = 1
		} else {
			bytes[0] = 0
		}
		return bytes, nil
	case reflect.TypeOf(CK_ULONG(0)):
		bytes := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bytes, uint32(v.Uint()))
		return bytes, nil
	case reflect.TypeOf(CK_DATE{}):
		var pa = new(CK_DATE)
		reflect.ValueOf(pa).Elem().Set(v)
		str := time.Time(*pa).Format("20060102")
		return []byte(str), nil
	case reflect.TypeOf(CK_KEY_TYPE(0)):
		bytes := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bytes, uint32(v.Uint()))
		return bytes, nil
	case reflect.TypeOf(CK_Bytes{}), reflect.TypeOf(CK_BigInt{}):
		a := v.Bytes()
		bytes := make([]byte, len(a))
		for i, b := range a {
			bytes[i] = b
		}
		return bytes, nil
	case reflect.TypeOf(CK_String("")):
		aAsBytes := []byte(v.String())
		bytes := make([]byte, len(aAsBytes))
		for i, b := range aAsBytes {
			bytes[i] = b
		}
		return bytes, nil
	case reflect.TypeOf(CK_OBJECT_CLASS(0)):
		bytes := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bytes, uint32(v.Uint()))
		return bytes, nil
	case reflect.TypeOf(CK_MECHANISM_TYPE(0)):
		bytes := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bytes, uint32(v.Uint()))
		return bytes, nil
	case reflect.TypeOf(CK_MECHANISM_TYPE_PTR{}):
		var a = make(CK_MECHANISM_TYPE_PTR, 0)
		va := reflect.ValueOf(&a).Elem()
		va.Set(v)
		bytes := make([]byte, len(a)*4)
		for i := 0; i < len(a); i += 1 {
			mt := (a)[i]
			binary.LittleEndian.PutUint32(bytes[i*4:i*4+4], uint32(mt))
		}
		return bytes, nil
	case reflect.TypeOf(CK_ATTRIBUTE_PTR{}):
		a := v.Bytes()
		bytes := make([]byte, len(a))
		for i, b := range a {
			bytes[i] = b
		}
		return bytes, nil
	default:
		return nil, fmt.Errorf("unsupported type: %s", v.Type().String())
	}
}
