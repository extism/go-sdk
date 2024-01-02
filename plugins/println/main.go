package main

import (
	"fmt"

	pdk "github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	input := pdk.InputString()
	fmt.Println("this was printed from the plugin", input)
	return 0
}

func main() {}
