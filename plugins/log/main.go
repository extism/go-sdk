package main

import (
	"fmt"

	pdk "github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	pdk.Log(pdk.LogTrace, "this is a trace log")
	pdk.Log(pdk.LogDebug, "this is a debug log")
	pdk.Log(pdk.LogInfo, "this is an info log")
	pdk.Log(pdk.LogWarn, "this is a warning log")
	pdk.Log(pdk.LogError, "this is an error log")

	return 0
}

func getU32(name string) (uint32, bool) {
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

	return uintFromLEBytes(array), true
}

func setU32(name string, value uint32) {
	pdk.SetVar(name, uintToLEBytes(value))
}

func uintFromLEBytes(bytes [4]byte) uint32 {
	return uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
}

func uintToLEBytes(num uint32) []byte {
	var bytes [4]byte
	bytes[0] = byte(num)
	bytes[1] = byte(num >> 8)
	bytes[2] = byte(num >> 16)
	bytes[3] = byte(num >> 24)
	return bytes[:]
}

func main() {}
