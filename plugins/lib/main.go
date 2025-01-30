package main

import (
	"strings"

	pdk "github.com/extism/go-pdk"
)

//go:export capitalize
func Capitalize(ptr uint64) uint64 {
	mem := pdk.FindMemory(ptr)
	bytes := mem.ReadBytes()
	capitalized := strings.ToUpper(string(bytes))
	out := pdk.AllocateString(capitalized)
	return out.Offset()
}

func main() {}
