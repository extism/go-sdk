package extism

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/sys"
)

// TODO: test WasmFile
// TODO: test WasmUrl
// TODO: test hash

func TestAlloc(t *testing.T) {
	manifest := manifest("alloc.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, _, err := plugin.Call("run_test", []byte{})

		assertCall(t, err, exit)
	}
}

func TestConfig(t *testing.T) {

	params := map[string]string{
		"hello": `{"config": "hello"}`,
		"":      `{"config": "<unset by host>"}`,
	}

	for k, v := range params {
		manifest := manifest("config.wasm")

		if k != "" {
			manifest.Config["thing"] = k
		}

		if plugin, ok := plugin(t, manifest); ok {
			defer plugin.Close()

			exit, output, err := plugin.Call("run_test", []byte{})

			if assertCall(t, err, exit) {
				actual := string(output)
				expected := v

				assert.Equal(t, expected, actual)
			}
		}
	}
}

func TestFail(t *testing.T) {
	manifest := manifest("fail.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, _, err := plugin.Call("run_test", []byte{})

		assert.Equal(t, uint32(1), exit, "Exit code must be 1")
		assert.Equal(t, "Some error message", err.Error())
	}
}

func TestHello(t *testing.T) {
	manifest := manifest("hello.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "Hello, world!"

			assert.Equal(t, expected, actual)
		}
	}
}

func TestExit(t *testing.T) {
	cases := map[string]uint32{
		"-1":  0xffffffff, // NOTE: wazero doesn't support negative exit codes
		"500": 500,
		"abc": 1,
		"":    2,
	}

	for config, expected := range cases {
		manifest := manifest("exit.wasm")

		if plugin, ok := plugin(t, manifest); ok {
			defer plugin.Close()

			if config != "" {
				plugin.Config["code"] = config
			}

			actual, _, err := plugin.Call("_start", []byte{})

			if actual != 0 {
				assert.NotNil(t, err, fmt.Sprintf("err can't be nil. config: %v", config))
			}

			fmt.Printf("err: %v", err)
			assert.Equal(t, expected, actual, fmt.Sprintf("exit must be %v. config: '%v'", expected, config))
		}
	}
}

func TestHost(t *testing.T) {
	manifest := manifest("host.wasm")

	mult := HostFunction{
		Name:      "mult",
		Namespace: "env",
		Callback: func(ctx context.Context, plugin *CurrentPlugin, inputs []uint64) []uint64 {
			a := api.DecodeI32(inputs[0])
			b := api.DecodeI32(inputs[1])

			return []uint64{api.EncodeI32(a * b)}
		},
		Params:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
		Results: []api.ValueType{api.ValueTypeI64},
	}

	if plugin, ok := plugin(t, manifest, mult); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "42 x 2 = 84"

			assert.Equal(t, expected, actual)
		}
	}
}

func TestHTTP_allowed(t *testing.T) {
	manifest := manifest("http.wasm")
	manifest.AllowedHosts = []string{"jsonplaceholder.*.com"}

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := `
{
	"userId": 1,
	"id": 1,
	"title": "delectus aut autem",
	"completed": false
}`

			assert.JSONEq(t, expected, actual)
		}
	}
}

func TestHTTP_denied(t *testing.T) {
	allowed := []string{
		"", // If no allowed hosts are defined, then all requests are denied
		"google.*"}

	for _, url := range allowed {
		manifest := manifest("http.wasm")
		if url != "" {
			manifest.AllowedHosts = []string{url}
		}

		if plugin, ok := plugin(t, manifest); ok {
			defer plugin.Close()

			exit, _, err := plugin.Call("run_test", []byte{})

			assert.Equal(t, uint32(1), exit, "HTTP Request must fail")
			assert.Contains(t, err.Error(), "HTTP request to 'https://jsonplaceholder.typicode.com/todos/1' is not allowed")
		}
	}
}

func TestLog_default(t *testing.T) {
	manifest := manifest("log.wasm")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	type LogEntry struct {
		message string
		level   LogLevel
	}

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, _, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			logs := buf.String()

			assert.Contains(t, logs, "this is a warning log")
			assert.Contains(t, logs, "this is an erorr log")
		}
	}
}

func TestLog_custom(t *testing.T) {
	manifest := manifest("log.wasm")

	type LogEntry struct {
		message string
		level   LogLevel
	}

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		actual := []LogEntry{}

		plugin.SetLogger(func(level LogLevel, message string) {
			actual = append(actual, LogEntry{message: message, level: level})
		})

		plugin.SetLogLevel(Info)

		exit, _, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			expected := []LogEntry{
				{message: "this is an info log", level: Info},
				{message: "this is a warning log", level: Warn},
				{message: "this is an erorr log", level: Error}}

			assert.Equal(t, expected, actual)
		}
	}
}

func TestTimeout(t *testing.T) {
	manifest := manifest("sleep.wasm")
	manifest.Config["duration"] = "3" // sleep for 3 seconds
	manifest.Timeout = 100            // 100ms

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, _, err := plugin.Call("run_test", []byte{})

		assert.Equal(t, sys.ExitCodeDeadlineExceeded, exit, "Exit code must be `sys.ExitCodeDeadlineExceeded`")
		assert.Equal(t, "module closed with context deadline exceeded", err.Error())
	}
}

func TestCancel(t *testing.T) {
	manifest := manifest("sleep.wasm")
	manifest.Config["duration"] = "3" // sleep for 3 seconds

	ctx, cancel := context.WithCancel(context.Background())
	config := wasiPluginConfig()

	plugin, err := NewPlugin(ctx, manifest, config, []HostFunction{})

	if err != nil {
		t.Errorf("Could not create plugin: %v", err)
	}

	defer plugin.Close()

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	exit, _, err := plugin.Call("run_test", []byte{})

	assert.Equal(t, sys.ExitCodeContextCanceled, exit, "Exit code must be `sys.ExitCodeContextCanceled`")
	assert.Equal(t, "module closed with context canceled", err.Error())
}

func TestVar(t *testing.T) {
	manifest := manifest("var.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		plugin.Var["a"] = uintToLEBytes(10)

		exit, _, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := uintFromLEBytes(plugin.Var["a"])
			expected := uint(20)

			assert.Equal(t, expected, actual)
		}
	}

}

func TestFS(t *testing.T) {
	manifest := manifest("fs.wasm")
	manifest.AllowedPaths = map[string]string{
		"testdata": "/mnt",
	}

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "hello world!"

			assert.Equal(t, expected, actual)
		}
	}
}

func TestCountVowels(t *testing.T) {
	manifest := manifest("count_vowels.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("count_vowels", []byte("hello world"))

		if assertCall(t, err, exit) {
			expected := 3 // 3 vowels

			var actual map[string]int
			json.Unmarshal(output, &actual)

			assert.Equal(t, expected, actual["count"])
		}
	}
}

func TestHelloHaskell(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	manifest := manifest("hello_haskell.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		plugin.SetLogLevel(Trace)
		plugin.Config["greeting"] = "Howdy"

		exit, output, err := plugin.Call("testing", []byte("John"))

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "Howdy, John"

			assert.Equal(t, expected, actual)

			logs := buf.String()

			assert.Contains(t, logs, "Initialized Haskell language runtime.")
			assert.Contains(t, logs, "Calling hs_exit")
		}
	}
}

func wasiPluginConfig() PluginConfig {
	level := Warn
	config := PluginConfig{
		ModuleConfig: wazero.NewModuleConfig().WithSysWalltime(),
		EnableWasi:   true,
		LogLevel:     &level,
	}
	return config
}

func manifest(name string) Manifest {
	manifest := Manifest{
		Wasm: []Wasm{
			WasmFile{
				Path: fmt.Sprintf("wasm/%v", name),
				Hash: "",
				Name: "main",
			},
		},
		Config:       make(map[string]string),
		AllowedHosts: []string{},
		AllowedPaths: make(map[string]string),
	}
	return manifest
}

func plugin(t *testing.T, manifest Manifest, funcs ...HostFunction) (*Plugin, bool) {
	ctx := context.Background()
	config := wasiPluginConfig()

	plugin, err := NewPlugin(ctx, manifest, config, funcs)

	if err != nil {
		t.Errorf("Could not create plugin: %v", err)
		return nil, false
	}

	return plugin, true
}

func assertCall(t *testing.T, err error, exit uint32) bool {
	if err != nil {
		t.Error(err)
		return false
	} else if exit != 0 {
		t.Errorf("Call failed. Exit code: %v", exit)
		return false
	}

	return true
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
