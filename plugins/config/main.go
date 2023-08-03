package main

import "github.com/extism/go-pdk"

//export run_test
func run_test() int32 {
	thing, ok := pdk.GetConfig("thing")

	if !ok {
		thing = "<unset by host>"
	}

	output := `{"config": "` + thing + `"}`
	mem := pdk.AllocateString(output)

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
