package pkcs11ks

import (
	"encoding/binary"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"math/big"
	"reflect"
	"time"
)

const CKK_RSA = CK_KEY_TYPE(p11api.CKK_RSA)
const CKK_EC = CK_KEY_TYPE(p11api.CKK_EC)
const CKK_ECDSA = CK_KEY_TYPE(p11api.CKK_ECDSA)
const CKK_AES = CK_KEY_TYPE(p11api.CKK_AES)

type CK_BBOOL bool

// From Pkcs11 spec: CK_ULONG will sometimes be 32 bits, and sometimes perhaps 64 bits
type CK_ULONG uint32
type CK_DATE time.Time
type CK_KEY_TYPE CK_ULONG
type CK_Bytes []byte
type CK_BigInt *big.Int
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
	switch len(bytes) {
	case 4:
		return CK_ULONG(binary.LittleEndian.Uint32(bytes)), nil
	case 8:
		return CK_ULONG(binary.LittleEndian.Uint64(bytes)), nil
	default:
		return 0, fmt.Errorf("wrong attr value size. Expected 4 or 8 , actual %d", len(bytes))
	}
}

func bytesFrom_CK_ULONG(a CK_ULONG, ckULONGIs32bit bool) []byte {
	if ckULONGIs32bit {
		bytes := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bytes, uint32(a))
		return bytes
	} else {
		bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		binary.LittleEndian.PutUint64(bytes, uint64(a))
		return bytes
	}
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

func bytesTo_CK_BigInt(bytes []byte) (CK_BigInt, error) {
	bi := big.NewInt(0)
	bi.SetBytes(bytes)
	return CK_BigInt(bi), nil
}

func bytesFrom_CK_BigInt(a CK_BigInt) []byte {
	return (*big.Int)(a).Bytes()
}

func bytesTo_CK_KEY_TYPE(bytes []byte) (CK_KEY_TYPE, error) {
	ul, err := bytesTo_CK_ULONG(bytes)
	return CK_KEY_TYPE(ul), err
}

func bytesFrom_CK_KEY_TYPE(a CK_KEY_TYPE, ckULONGIs32Bit bool) []byte {
	return bytesFrom_CK_ULONG(CK_ULONG(a), ckULONGIs32Bit)
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
	ul, err := bytesTo_CK_ULONG(bytes)
	return CK_OBJECT_CLASS(ul), err
}

func bytesFrom_CK_OBJECT_CLASS(a CK_OBJECT_CLASS, ckULONGIs32Bit bool) []byte {
	return bytesFrom_CK_ULONG(CK_ULONG(a), ckULONGIs32Bit)
}
func bytesTo_CK_MECHANISM_TYPE(bytes []byte) (CK_MECHANISM_TYPE, error) {
	ul, err := bytesTo_CK_ULONG(bytes)
	return CK_MECHANISM_TYPE(ul), err
}

func bytesFrom_CK_MECHANISM_TYPE(a CK_MECHANISM_TYPE, ckULONGIs32Bit bool) []byte {
	return bytesFrom_CK_ULONG(CK_ULONG(a), ckULONGIs32Bit)
}

func bytesTo_CK_MECHANISM_TYPE_PTR(bytes []byte, ckULONGIs32Bit bool) (CK_MECHANISM_TYPE_PTR, error) {
	ckULONGSize := 8
	if ckULONGIs32Bit {
		ckULONGSize = 4
	}
	if len(bytes)%ckULONGSize != 0 {
		return nil, fmt.Errorf("wrong attr value size. Expected mod %d == 0, actual %d", ckULONGSize, len(bytes))
	}
	x := make([]CK_MECHANISM_TYPE, len(bytes)/ckULONGSize)
	for i := 0; i < len(bytes)/ckULONGSize; i += 1 {
		itemBytes := bytes[i*ckULONGSize : i*ckULONGSize+ckULONGSize]
		mt, err := bytesTo_CK_ULONG(itemBytes)
		if err != nil {
			return nil, err
		}
		(x)[i] = CK_MECHANISM_TYPE(mt)
	}
	return x, nil
}

func bytesFrom_CK_MECHANISM_TYPE_PTR(a CK_MECHANISM_TYPE_PTR, ckULONGIs32Bit bool) []byte {
	ckULONGSize := 8
	if ckULONGIs32Bit {
		ckULONGSize = 4
	}
	bytes := make([]byte, len(a)*ckULONGSize)
	for i := 0; i < len(a); i += 1 {
		mt := a[i]
		itemBytes := bytesFrom_CK_MECHANISM_TYPE(mt, ckULONGIs32Bit)
		copy(bytes[i*ckULONGSize:i*ckULONGSize+ckULONGSize], itemBytes)
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

func ckValueSetFromBytes(bytes []byte, v reflect.Value, ckULONGIs32bit bool) error {
	switch v.Type() {
	case reflect.TypeOf(CK_BBOOL(false)):
		if len(bytes) != 1 {
			return fmt.Errorf("wrong attr value size. Expected %d, actual %d", 1, len(bytes))
		}

		v.SetBool(bytes[0] != 0)
		return nil
	case reflect.TypeOf(CK_ULONG(0)):
		ui, err := bytesTo_CK_ULONG(bytes)
		v.SetUint(uint64(ui))
		return err
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
		ui, err := bytesTo_CK_KEY_TYPE(bytes)
		v.SetUint(uint64(ui))
		return err
	case reflect.TypeOf(CK_Bytes{}):
		x := make([]byte, len(bytes))
		for i, b := range bytes {
			(x)[i] = b
		}
		v.SetBytes(x)
		return nil
	case reflect.TypeOf(CK_BigInt(nil)):
		bi := big.NewInt(0)
		bi.SetBytes(bytes)
		v.Set(reflect.ValueOf(CK_BigInt(bi)))
		return nil
	case reflect.TypeOf(CK_String("")):
		buff := make([]byte, len(bytes))
		for i, b := range bytes {
			buff[i] = b
		}
		v.SetString(string(buff))
		return nil
	case reflect.TypeOf(CK_OBJECT_CLASS(0)):
		ui, err := bytesTo_CK_OBJECT_CLASS(bytes)
		v.SetUint(uint64(ui))
		return err
	case reflect.TypeOf(CK_MECHANISM_TYPE(0)):
		ui, err := bytesTo_CK_MECHANISM_TYPE(bytes)
		v.SetUint(uint64(ui))
		return err
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

func ckValueWriteToBytes(v reflect.Value, ckULONGIs32bit bool) ([]byte, error) {
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
		return bytesFrom_CK_ULONG(CK_ULONG(v.Uint()), ckULONGIs32bit), nil
	case reflect.TypeOf(CK_DATE{}):
		var pa = new(CK_DATE)
		reflect.ValueOf(pa).Elem().Set(v)
		str := time.Time(*pa).Format("20060102")
		return []byte(str), nil
	case reflect.TypeOf(CK_KEY_TYPE(0)):
		return bytesFrom_CK_KEY_TYPE(CK_KEY_TYPE(v.Uint()), ckULONGIs32bit), nil
	case reflect.TypeOf(CK_Bytes{}):
		a := v.Bytes()
		bytes := make([]byte, len(a))
		for i, b := range a {
			bytes[i] = b
		}
		return bytes, nil
	case reflect.TypeOf(CK_BigInt(nil)):
		var bi = big.NewInt(0)
		vbi := reflect.ValueOf(bi)
		if v.IsNil() {
			return []byte{}, nil
		}
		vbi.Elem().Set(v.Elem())
		bytes := (*big.Int)(bi).Bytes()
		return bytes, nil

	case reflect.TypeOf(CK_String("")):
		aAsBytes := []byte(v.String())
		bytes := make([]byte, len(aAsBytes))
		for i, b := range aAsBytes {
			bytes[i] = b
		}
		return bytes, nil
	case reflect.TypeOf(CK_OBJECT_CLASS(0)):
		return bytesFrom_CK_OBJECT_CLASS(CK_OBJECT_CLASS(v.Uint()), ckULONGIs32bit), nil
	case reflect.TypeOf(CK_MECHANISM_TYPE(0)):
		return bytesFrom_CK_MECHANISM_TYPE(CK_MECHANISM_TYPE(v.Uint()), ckULONGIs32bit), nil
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
