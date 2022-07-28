package pkcs11ks

import (
	"encoding/binary"
	"fmt"
	"github.com/bukodi/go-keystores"
	p11api "github.com/miekg/pkcs11"
	"reflect"
	"time"
)

type CkValue interface {
	readToValue(bytes []byte, v reflect.Value) error
	writeFromValue(v reflect.Value) ([]byte, error)
}

type CkType[T any] interface {
	read(bytes []byte) (T, error)
	write() ([]byte, error)
}

type CK_BBOOL bool

var _ CkType[CK_BBOOL] = CK_BBOOL(false)

type CK_ULONG uint32

var _ CkType[CK_ULONG] = CK_ULONG(0)

type CK_DATE time.Time

var _ CkType[CK_DATE] = CK_DATE(time.Time{})

type CK_KEY_TYPE CK_ULONG

var _ CkType[CK_KEY_TYPE] = CK_KEY_TYPE(0)

const CKK_RSA = CK_KEY_TYPE(p11api.CKK_RSA)
const CKK_EC = CK_KEY_TYPE(p11api.CKK_EC)
const CKK_ECDSA = CK_KEY_TYPE(p11api.CKK_ECDSA)
const CKK_AES = CK_KEY_TYPE(p11api.CKK_AES)

type CK_Bytes []byte

var _ CkType[CK_Bytes] = CK_Bytes([]byte{})

type CK_String string

var _ CkType[CK_String] = CK_String("")

type CK_MECHANISM_TYPE CK_ULONG

var _ CkType[CK_MECHANISM_TYPE] = CK_MECHANISM_TYPE(0)

type CK_MECHANISM_TYPE_PTR []CK_MECHANISM_TYPE

var _ CkType[CK_MECHANISM_TYPE_PTR] = CK_MECHANISM_TYPE_PTR([]CK_MECHANISM_TYPE{})

type CK_ATTRIBUTE_PTR CK_Bytes

var _ CkType[CK_ATTRIBUTE_PTR] = CK_ATTRIBUTE_PTR([]byte{})

func (a CK_BBOOL) read(bytes []byte) (CK_BBOOL, error) {
	if len(bytes) != 1 {
		return false, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 1, len(bytes))
	}

	return bytes[0] != 0, nil
}

func (a CK_BBOOL) write() ([]byte, error) {
	bytes := []byte{0}
	if a {
		bytes[0] = 1
	} else {
		bytes[0] = 0
	}
	return bytes, nil
}

func ckValueSetFromBytes(bytes []byte, v reflect.Value) error {
	switch v.Type() {
	case reflect.TypeOf(CK_BBOOL(false)):
		if len(bytes) != 1 {
			return fmt.Errorf("wrong attr value size. Expected %d, actual %d", 1, len(bytes))
		}

		v.SetBool(bytes[0] != 0)
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
	default:
		return nil, fmt.Errorf("unsupported type: %s", v.Type().String())
	}
}

func (a CK_BBOOL) writeFromValue(v reflect.Value) ([]byte, error) {
	bytes := []byte{0}
	if v.Bool() {
		bytes[0] = 1
	} else {
		bytes[0] = 0
	}
	return bytes, nil
}

func (a CK_ULONG) read(bytes []byte) (CK_ULONG, error) {
	if len(bytes) != 4 {
		return 0, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 4, len(bytes))
	}
	return CK_ULONG(binary.LittleEndian.Uint32(bytes)), nil
}

func (a CK_ULONG) write() ([]byte, error) {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes, nil
}

func (a CK_DATE) read(bytes []byte) (CK_DATE, error) {
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

func (a CK_DATE) write() ([]byte, error) {
	str := time.Time(a).Format("20060102")
	return []byte(str), nil
}

func (a CK_KEY_TYPE) read(bytes []byte) (CK_KEY_TYPE, error) {
	if len(bytes) != 4 {
		return 0, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 4, len(bytes))
	}
	return CK_KEY_TYPE(binary.LittleEndian.Uint32(bytes)), nil
}

func (a CK_KEY_TYPE) write() ([]byte, error) {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes, nil
}

func (a CK_Bytes) read(bytes []byte) (CK_Bytes, error) {
	x := make([]byte, len(bytes))
	for i, b := range bytes {
		(x)[i] = b
	}
	return x, nil
}

func (a CK_Bytes) write() ([]byte, error) {
	bytes := make([]byte, len(a))
	for i, b := range a {
		bytes[i] = b
	}
	return bytes, nil
}

func (a CK_ATTRIBUTE_PTR) read(bytes []byte) (CK_ATTRIBUTE_PTR, error) {
	x := make([]byte, len(bytes))
	for i, b := range bytes {
		(x)[i] = b
	}
	return x, nil
}

func (a CK_ATTRIBUTE_PTR) write() ([]byte, error) {
	bytes := make([]byte, len(a))
	for i, b := range a {
		bytes[i] = b
	}
	return bytes, nil
}

func (a CK_String) read(bytes []byte) (CK_String, error) {
	buff := make([]byte, len(bytes))
	for i, b := range bytes {
		buff[i] = b
	}
	str := string(buff)
	return CK_String(str), nil
}

func (a CK_String) write() ([]byte, error) {
	aAsBytes := []byte(a)
	bytes := make([]byte, len(aAsBytes))
	for i, b := range aAsBytes {
		bytes[i] = b
	}
	return bytes, nil
}

func (a CK_MECHANISM_TYPE) read(bytes []byte) (CK_MECHANISM_TYPE, error) {
	if len(bytes) != 4 {
		return 0, fmt.Errorf("wrong attr value size. Expected %d, actual %d", 4, len(bytes))
	}
	return CK_MECHANISM_TYPE(binary.LittleEndian.Uint32(bytes)), nil
}

func (a CK_MECHANISM_TYPE) write() ([]byte, error) {
	bytes := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bytes, uint32(a))
	return bytes, nil
}

func (a CK_MECHANISM_TYPE_PTR) read(bytes []byte) (CK_MECHANISM_TYPE_PTR, error) {
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

func (a CK_MECHANISM_TYPE_PTR) write() ([]byte, error) {
	bytes := make([]byte, len(a)*4)
	for i := 0; i < len(a); i += 1 {
		mt := (a)[i]
		binary.LittleEndian.PutUint32(bytes[i*4:i*4+4], uint32(mt))
	}
	return bytes, nil
}
