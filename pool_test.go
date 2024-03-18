package extism

import (
	"context"
	"log"
	"sync"
	"testing"
	"time"
)

func runTest(wg *sync.WaitGroup, pool *Pool, n int) {
	defer wg.Done()
	time.Sleep(time.Millisecond * time.Duration(n))
	var data string
	pool.WithPlugin(context.Background(), "test", time.Second, func(plugin *Plugin) error {
		_, x, err := plugin.Call("count_vowels", []byte("aaa"))
		data = string(x)
		return err
	})
	log.Println(string(data))
}

func TestPluginPool(t *testing.T) {
	pool := NewPool(2)
	manifest := Manifest{
		Wasm: []Wasm{
			WasmFile{
				Path: "../code.wasm",
			},
		},
	}

	pool.Add("test", func(ctx context.Context) (*Plugin, error) {
		return NewPlugin(ctx, manifest, PluginConfig{}, []HostFunction{})
	})

	wg := &sync.WaitGroup{}
	wg.Add(10)
	go runTest(wg, pool, 1000)
	go runTest(wg, pool, 1000)
	go runTest(wg, pool, 1000)
	go runTest(wg, pool, 1000)
	go runTest(wg, pool, 1000)
	go runTest(wg, pool, 500)
	go runTest(wg, pool, 500)
	go runTest(wg, pool, 500)
	go runTest(wg, pool, 500)
	go runTest(wg, pool, 500)
	wg.Wait()
}
