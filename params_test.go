package keystores

import (
	"encoding/json"
	"testing"

	"github.com/bukodi/go-keystores/utils"
)

func TestValueMap(t *testing.T) {
	userPINParamType := NewDescriptor("userPIN", "Label of the", utils.SensitiveString(""), true)

	params := NewParams()
	SetValue(params, userPINParamType, utils.SensitiveString("1234"))
	pin, err := GetValue(params, userPINParamType)
	if err != nil {
		t.Errorf("%+v", err)
	}
	t.Logf("User PIN: %v", string(pin))

	anyMap := params.AsMap()
	t.Logf("As map: %v", anyMap)

	jsonBytes, err := json.Marshal(anyMap)
	if err != nil {
		t.Errorf("%+v", err)
	}
	t.Logf("JSON: %s", string(jsonBytes))

	map2 := make(map[string]interface{})
	map2["userPIN"] = utils.SensitiveString("5678")
	err = SetFromMap(params, map2)
	if err != nil {
		t.Errorf("%+v", err)
	}
}
