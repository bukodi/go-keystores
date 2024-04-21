package compositeks

import "github.com/bukodi/go-keystores"

type provider struct {
	provInstance keystores.Provider
	options      any
}

type ks struct {
	ksInstance keystores.KeyStore
	options    any
}

// TODO: make this thread safe
var provInstances = make([]provider, 0)
var ksInstances = make([]ks, 0)

func RegisterProvider(instance keystores.Provider, options any) {
	provInstances = append(provInstances, provider{instance, options})
}

func RegisterKeystore(instance keystores.KeyStore, options any) {
	ksInstances = append(ksInstances, ks{instance, options})
}
