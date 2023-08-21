package pkcs11ks

import (
	"fmt"
	p11api "github.com/miekg/pkcs11"
)

func dumpAttrs(attrs []*p11api.Attribute) string {
	if len(attrs) == 0 {
		return "empty attr list"
	}
	var msg = ""
	for _, attr := range attrs {
		line := ""
		if attrDesc := CkaDescByCode(attr.Type); attrDesc == nil {
			line = fmt.Sprintf("UNKNOWN ATTR TYPE #%04x", attr.Type)
		} else {
			line = fmt.Sprintf("%s #%04x", attrDesc.name, attr.Type)
		}
		line = fmt.Sprintf("%20s : %2d bytes %+v", line, len(attr.Value), attr.Value)
		msg += line + "\n"
	}
	return msg
}
