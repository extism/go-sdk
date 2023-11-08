package main

import (
	"github.com/extism/go-pdk"
)

//go:wasm-module extism:host/user
//export hostPurpleMessage
func hostPurpleMessage(offset uint64) uint64

func purpleMessage(message string) pdk.Memory {
	messageMemory := pdk.AllocateString(message)
	off := hostPurpleMessage(messageMemory.Offset())
	return pdk.FindMemory(off)
}

//go:wasm-module extism:host/user
//export hostGreenMessage
func hostGreenMessage(offset uint64) uint64

func greenMessage(message string) pdk.Memory {
	messageMemory := pdk.AllocateString(message)
	off := hostGreenMessage(messageMemory.Offset())
	return pdk.FindMemory(off)
}

//go:wasm-module extism:host/user
//export say_purple
func say_purple() int32 {
	input := pdk.InputString()
	output := "👋 Hello from say_purple " + input

	mem := purpleMessage(output)

	pdk.OutputMemory(mem)
	return 0

}

//go:wasm-module extism:host/user
//export say_green
func say_green() int32 {
	input := pdk.Input()
	output := "🫱 Hey from say_green " + string(input)

	mem := greenMessage(output)

	pdk.OutputMemory(mem)
	return 0

}
func main() {}
