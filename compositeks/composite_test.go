package compositeks

import (
	"github.com/bukodi/go-keystores/inmemoryks"
	"testing"
)

func TestCompositeProvider(t *testing.T) {
	ks1 := inmemoryks.CreateInMemoryKeyStore()
	ks2 := inmemoryks.CreateInMemoryKeyStore()

	RegisterKeystore(ks1, nil)
	RegisterKeystore(ks2, nil)

}
