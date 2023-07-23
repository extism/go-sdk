package main

import (
	"context"
	"fmt"

	extism "github.com/extism/go-sdk"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func main() {
	ctx := context.Background()

	funcs := []extism.HostFunction{
		{
			Name:      "mult",
			Namespace: "host",
			Callback: func(ctx context.Context, plugin *extism.CurrentPlugin, inputs []uint64) []uint64 {
				a := api.DecodeI32(inputs[0])
				b := api.DecodeI32(inputs[1])

				return []uint64{api.EncodeI32(a * b)}
			},
			Params:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
			Results: []api.ValueType{api.ValueTypeI64},
		},
	}

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
				Path: "host.wasm",
			},
			// extism.WasmUrl{
			// 	Url: "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm",
			// },
		},
		Config: map[string]string{
			"thing": "config from host",
		},
		AllowedHosts: []string{
			"google.*",
			"jsonplaceholder.*.com",
		},
	}

	plugin, err := r.NewPlugin(manifest, wazero.NewModuleConfig(), funcs)
	if err != nil {
		fmt.Println("Could not create plugin: ", err)
		return
	}

	plugin.Var["a"] = uintToLEBytes(10)

	exit, output, err := plugin.Call("run_test", []byte{})

	a := uintFromLEBytes(plugin.Var["a"])

	if err != nil {
		fmt.Printf("Error during call: %v\n", err)
	} else if exit != 0 {
		fmt.Printf("Invalid exti coe: %v\n", exit)
	} else {
		str := string(output)
		fmt.Println("output:", str)
		fmt.Printf("a: %v\n", a)
	}
}

func uintToLEBytes(num uint) []byte {
	var bytes [4]byte
	bytes[0] = byte(num)
	bytes[1] = byte(num >> 8)
	bytes[2] = byte(num >> 16)
	bytes[3] = byte(num >> 24)
	return bytes[:]
}

func uintFromLEBytes(bytes []byte) uint {
	return uint(bytes[0]) | uint(bytes[1])<<8 | uint(bytes[2])<<16 | uint(bytes[3])<<24
}
