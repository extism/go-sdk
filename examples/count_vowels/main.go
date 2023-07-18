package main

import (
	"context"
	"encoding/json"
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

	wasm, err := ioutil.ReadFile("count_vowels.wasm")
	if err != nil {
		fmt.Printf("Could not read file: %v\n", err)
		return
	}

	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmData{
				Data: wasm,
			},
		},
	}

	plugin, err := r.NewPlugin(manifest, wazero.NewModuleConfig())

	exit, output, err := plugin.Call("count_vowels", []byte("hello world"))

	if err != nil {
		fmt.Printf("Error during call: %v\n", err)
	} else if exit != 0 {
		fmt.Printf("Invalid exti coe: %v\n", exit)
	} else {
		// "out" is []byte type, and the plugin sends back json, so deserialize it into a map.
		// expect this object: `{"count": n}`
		var dest map[string]int
		json.Unmarshal(output, &dest)

		fmt.Println("Count:", dest["count"])
	}
}
