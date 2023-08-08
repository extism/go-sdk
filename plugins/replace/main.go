package main

import (
	"strings"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	input := pdk.InputString()

	output := strings.ReplaceAll(input, "test", "wasm")
	mem := pdk.AllocateString(output)

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
