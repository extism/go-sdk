package main

import (
	"fmt"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	a, ok := getU32("a")

	if !ok {
		a = -100
	}

	a *= 2

	output := fmt.Sprintf("a: %v", a)
	mem := pdk.AllocateString(output)

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func getU32(name string) (int, bool) {
	bytes := pdk.GetVar(name)
	if bytes == nil {
		return 0, false
	} else if len(bytes) != 4 {
		panic(fmt.Sprintf("Expected a byte slice of length 4 but got %d", len(bytes)))
	}

	var array [4]byte
	for i := 0; i < 4; i++ {
		array[i] = bytes[i]
	}

	return intFromLEBytes(array), true
}

func intFromLEBytes(bytes [4]byte) int {
	return int(bytes[0]) | int(bytes[1])<<8 | int(bytes[2])<<16 | int(bytes[3])<<24
}

func main() {}
