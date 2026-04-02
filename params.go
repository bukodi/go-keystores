package keystores

import (
	"log/slog"
	"reflect"

	"github.com/bukodi/go-keystores/utils"
)

type Descriptor[T any] interface {
	Name() string
	Description() string
	DefaultValue() (T, bool)
}

type descriptor[T any] struct {
	name            string
	description     string
	defaultValue    T
	hasDefaultValue bool
}

func (i descriptor[T]) Name() string {
	return i.name
}

func (i descriptor[T]) Description() string {
	return i.description
}

func (i descriptor[T]) DefaultValue() (T, bool) {
	return i.defaultValue, i.hasDefaultValue
}

var _ Descriptor[string] = descriptor[string]{}

func NewDescriptor[T any](name, description string, defaultValue T, hasDefaultValue bool) Descriptor[T] {
	return descriptor[T]{name, description, defaultValue, hasDefaultValue}
}

type ValueMap struct {
	descMap  map[string]any
	valueMap map[string]any
}

func NewParams(desc ...Descriptor[any]) ValueMap {
	vm := ValueMap{
		descMap:  make(map[string]any),
		valueMap: make(map[string]any),
	}
	for _, d := range desc {
		vm.descMap[d.Name()] = d
	}
	return vm
}

func SetValue[T any](vm ValueMap, desc Descriptor[T], v T) {
	name := desc.Name()
	vm.descMap[name] = desc
	vm.valueMap[name] = v
}

func GetValue[T any](vm ValueMap, desc Descriptor[T]) (T, error) {
	name := desc.Name()
	defValue, hasDefault := desc.DefaultValue()
	_, isDesc := vm.descMap[name]
	if !isDesc {
		if !hasDefault {
			return defValue, utils.HandleErrorMsg("Value not in map, and has no default value", nil,
				slog.String("name", name),
			)
		} else {
			return defValue, nil
		}
	} else {
		v := vm.valueMap[name]
		typedValue, ok := v.(T)
		if ok {
			return typedValue, nil
		} else {
			return defValue, utils.HandleErrorMsg("Wrong type of value", nil,
				slog.String("name", name),
				slog.String("actualType", reflect.TypeOf(v).String()),
				slog.String("expectedType", reflect.TypeOf(defValue).String()),
			)
		}
	}
}

func (vm ValueMap) AsMap() map[string]any {
	ret := make(map[string]any)
	for name, untypedDesc := range vm.descMap {
		v, hasValue := vm.valueMap[name]
		if hasValue {
			ret[name] = v
			continue
		}
		typedDesc, ok := untypedDesc.(Descriptor[any])
		if !ok {
			continue
		}
		defValue, hasDefault := typedDesc.DefaultValue()
		if hasDefault {
			ret[name] = defValue
		}
	}
	return ret
}

func SetFromMap(vm ValueMap, values map[string]any) error {
	for name, value := range values {
		desc, hasDesc := vm.descMap[name]
		if !hasDesc {
			continue
		}
		vm.valueMap[name] = value
		defValue, _ := desc.(Descriptor[any]).DefaultValue()
		if reflect.TypeOf(value) == reflect.TypeOf(defValue) {
			utils.HandleErrorMsg("Wrong type of value", nil,
				slog.String("name", name),
				slog.String("actualType", reflect.TypeOf(value).String()),
				slog.String("expectedType", reflect.TypeOf(defValue).String()),
			)
		}
	}
	return nil
}
