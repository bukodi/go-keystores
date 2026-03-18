package keystores

import "reflect"

type ParamType[V any] interface {
	Name() string
	Description() string
	DefaultValue() (V, bool)
}

type ParamValue[V any] interface {
	Type() ParamType[V]
	Value() (V, bool)
}

type paramType[V any] struct {
	name            string
	description     string
	defaultValue    V
	hasDefaultValue bool
}

type paramValue[V any] struct {
	paramType ParamType[V]
	value     V
	isSet     bool
}

func (p paramValue[V]) Type() ParamType[V] {
	return p.paramType
}

func (p paramValue[V]) Value() (V, bool) {
	return p.value, p.isSet
}

func (i paramType[V]) Name() string {
	return i.name
}

func (i paramType[V]) Description() string {
	return i.description
}

func (i paramType[V]) DefaultValue() (V, bool) {
	return i.defaultValue, i.hasDefaultValue
}

var _ ParamType[string] = paramType[string]{}

var _ ParamValue[string] = paramValue[string]{}

func NewParamType[V any](name, description string, defaultValue V, hasDefaultValue bool) ParamType[V] {
	return paramType[V]{name, description, defaultValue, hasDefaultValue}
}

func NewParamValue[V any](paramType ParamType[V], value V) ParamValue[V] {
	isSet := !reflect.ValueOf(value).IsZero()

	return paramValue[V]{paramType, value, isSet}
}
