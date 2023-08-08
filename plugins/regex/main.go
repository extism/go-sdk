package main

import (
	"regexp"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	r := regexp.MustCompile(`\b\w{4}\b`)
	input := pdk.InputString()

	//output := strings.ReplaceAll(input, "test", "wasm")
	output := r.ReplaceAllString(input, "wasm")
	mem := pdk.AllocateString(output)

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
