package main

import "github.com/extism/go-pdk"

//export run_test
func run_test() int32 {
	pdk.SetErrorString("my custom error")
	return 1
}

func main() {}
