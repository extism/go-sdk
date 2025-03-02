//go:build std
// +build std

package main

import (
	"github.com/extism/go-pdk"
)

func main() {
	input := pdk.InputString()

	pdk.OutputString("hello " + input)
}
