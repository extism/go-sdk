package main

import (
	"fmt"

	"github.com/extism/go-pdk"
)

//go:wasm-module env
//export mult
func mult(x, y uint64) uint64

//export run_test
func run_test() int32 {
	r := mult(42, 2)

	output := fmt.Sprintf("42 x 2 = %v", r)
	mem := pdk.AllocateString(output)

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
