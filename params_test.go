package keystores

import (
	"testing"

	"github.com/bukodi/go-keystores/utils"
)

func TestStringParam(t *testing.T) {

	labelParamType := NewParamType("label", "Label of the key", "", true)

	signLabel := NewParamValue(labelParamType, "")

	value, isSet := signLabel.Value()
	t.Logf("Label: %v, %t", value, isSet)

}

func TestSensitiveStringParam(t *testing.T) {

	userPINParamType := NewParamType("userPIN", "Label of the", utils.SensitiveString(""), true)

	userPIN := NewParamValue(userPINParamType, "1234")

	value, isSet := userPIN.Value()
	t.Logf("User PIN: %v, %t", value, isSet)

}
