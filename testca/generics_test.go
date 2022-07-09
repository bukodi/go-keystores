package testca

import (
	"fmt"
	"testing"
)

type A struct {
	ID      string
	AMember string
}
type B struct {
	ID      string
	BMember string
}

type IElem interface {
	Id() string
	SetId(string)
}

func (s *A) Id() string     { return s.ID }
func (s *A) SetId(i string) { s.ID = i }
func (s *B) Id() string     { return s.ID }
func (s *B) SetId(i string) { s.ID = i }

type IStore[T IElem] interface {
	add(item T)
}

type AStore struct {
	values map[string]*A
}

func (as *AStore) add(item *A) {

}

var _ IStore[*A] = &AStore{}

type MyStore[T IElem] struct {
	values map[string]T
}

func (s *MyStore[T]) add(item T) {
	item.SetId("aa")
	s.values["aa"] = item
}

func TestGenerics(t *testing.T) {
	var storeA = &MyStore[*A]{}
	storeA.values = make(map[string]*A)
	a := &A{}
	a.SetId("aaa")

	storeA.add(a)

	fmt.Println(a.Id())
}
