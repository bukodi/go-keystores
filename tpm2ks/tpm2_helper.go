package tpm2ks

import (
	"github.com/google/go-tpm/tpm2"
	"strings"
)

func printKeyAttributes(kAttrs tpm2.KeyProp) string {
	flags := make([]string, 0)
	if kAttrs&tpm2.FlagFixedTPM > 0 {
		flags = append(flags, "FixedTPM")
	}

	if kAttrs&tpm2.FlagStClear > 0 {
		flags = append(flags, "StClear")
	}
	if kAttrs&tpm2.FlagFixedParent > 0 {
		flags = append(flags, "FixedParent")
	}
	if kAttrs&tpm2.FlagSensitiveDataOrigin > 0 {
		flags = append(flags, "SensitiveDataOrigin")
	}

	if kAttrs&tpm2.FlagUserWithAuth > 0 {
		flags = append(flags, "UserWithAuth")
	}
	if kAttrs&tpm2.FlagAdminWithPolicy > 0 {
		flags = append(flags, "AdminWithPolicy")
	}
	if kAttrs&tpm2.FlagNoDA > 0 {
		flags = append(flags, "NoDA")
	}
	if kAttrs&tpm2.FlagRestricted > 0 {
		flags = append(flags, "Restricted")
	}
	if kAttrs&tpm2.FlagDecrypt > 0 {
		flags = append(flags, "Decrypt")
	}
	if kAttrs&tpm2.FlagSign > 0 {
		flags = append(flags, "Sign")
	}

	return strings.Join(flags, " ")
}
