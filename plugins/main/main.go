package main

import (
	"github.com/extism/go-pdk"
)

//go:wasm-module lib
//export capitalize
func Capitalize(offset uint64) uint64

//go:export run_test
func run_test() int32 {
	name := pdk.InputString()

	ptr := pdk.AllocateString(name)
	capitalizedPtr := Capitalize(ptr.Offset())
	capitalizedMem := pdk.FindMemory(capitalizedPtr)
	capitalized := string(capitalizedMem.ReadBytes())

	pdk.OutputString("Hello, " + capitalized)
	return 0
}

func main() {}
