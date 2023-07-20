package main

import (
	"context"
	"fmt"

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

	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmFile{
				Path: "var.wasm",
			},
			// extism.WasmUrl{
			// 	Url: "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm",
			// },
		},
		Config: map[string]string{
			"thing": "config from host",
		},
	}

	plugin, err := r.NewPlugin(manifest, wazero.NewModuleConfig())
	if err != nil {
		fmt.Println("Could not create plugin: ", err)
		return
	}

	plugin.Var["a"] = intToLEBytes(10)

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

func intToLEBytes(num int) []byte {
	var bytes [4]byte
	bytes[0] = byte(num)
	bytes[1] = byte(num >> 8)
	bytes[2] = byte(num >> 16)
	bytes[3] = byte(num >> 24)
	return bytes[:]
}
