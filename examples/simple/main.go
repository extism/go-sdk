package main

import (
	"context"
	"fmt"
	"io/ioutil"

	extism "github.com/extism/go-sdk"
	"github.com/tetratelabs/wazero"
)

func main() {
	ctx := context.Background()
	r, err := extism.NewRuntime(ctx)
	if err != nil {
		fmt.Printf("Could not initialize runtime: %v\n", err)
		return
	} else {
		defer r.Close()
	}

	r = r.WithWasi()

	wasm, err := ioutil.ReadFile("hello.wasm")
	if err != nil {
		fmt.Printf("Could not read file: %v\n", err)
		return
	}

	plugin, err := r.NewPlugin(wasm, wazero.NewModuleConfig())

	exit, output, err := plugin.Call("run_test", []byte{})

	if err != nil {
		fmt.Printf("Error during call: %v\n", err)
	} else if exit != 0 {
		fmt.Printf("Invalid exti coe: %v\n", exit)
	} else {
		str := string(output)
		fmt.Println("output:", str)
	}
}
