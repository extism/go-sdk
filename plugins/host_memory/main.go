package main

import (
	"fmt"

	"github.com/extism/go-pdk"
)

//go:wasm-module host
//export to_upper
func to_upper(offset uint64) uint64

//export run_test
func run_test() int32 {
	name := pdk.InputString()

	// Store the message in the wasm memory and get an pointer for the location
	message := fmt.Sprintf("Hello %s!", name)
	mem := pdk.AllocateString(message)

	pdk.Log(pdk.LogError, fmt.Sprintf("offset: %v, length: %v", mem.Offset(), mem.Length()))

	// Send the pointer of the message to to_upper and get back
	// a new pointer for the new transformed message
	offset := to_upper(mem.Offset())
	mem = pdk.FindMemory(offset)

	pdk.Log(pdk.LogError, fmt.Sprintf("offset: %v, length: %v", offset, mem.Length()))

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
