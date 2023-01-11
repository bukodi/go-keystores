package tpm2ks

import (
	"crypto/sha256"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"io"
	"strings"
)

func printKey(f io.ReadWriter, ctxBytes []byte, title string) string {
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("%s: \n", title))
	hCtx, err := tpm2.ContextLoad(f, ctxBytes)
	if err != nil {
		return err.Error()
	}
	defer tpm2.FlushContext(f, hCtx)

	tpmPubKey, name, qname, err := tpm2.ReadPublic(f, hCtx)
	if err != nil {
		return err.Error()
	}
	msg.WriteString(fmt.Sprintf("  Name : %x-%x\n", name[0:2], name[2:]))
	msg.WriteString(fmt.Sprintf("  QName: %x-%x\n", qname[0:2], qname[2:]))
	msg.WriteString(fmt.Sprintf("  Type : %s\n", tpmPubKey.Type))
	msg.WriteString(fmt.Sprintf("  NameAlg: %s\n", tpmPubKey.NameAlg))
	msg.WriteString(fmt.Sprintf("  Attrs: %s\n", printKeyAttributes(tpmPubKey.Attributes)))
	msg.WriteString(fmt.Sprintf("  AuthPolicy: %x\n", tpmPubKey.AuthPolicy))

	publicBlob, err := tpmPubKey.Encode()
	if err != nil {
		return err.Error()
	}
	msg.WriteString(fmt.Sprintf("  Calculated name: %x\n", sha256.Sum256(publicBlob)))
	return msg.String()
}

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
