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

func TestWasmUrl(t *testing.T) {
	url := "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm"
	wasm := WasmUrl{
		Url:  url,
		Name: "code",
		Hash: "7def5bb4aa3843a5daf5d6078f1e8540e5ef10b035a9d9387e9bd5156d2b2565",
	}

	manifest := Manifest{
		Wasm:         []Wasm{wasm},
		Config:       make(map[string]string),
		AllowedHosts: []string{},
		AllowedPaths: make(map[string]string),
	}

	_, ok := plugin(t, manifest)
	assert.True(t, ok, "Plugin must be succussfuly created")
}

func TestHashMismatch(t *testing.T) {
	wasm := WasmFile{
		Path: "wasm/alloc.wasm",
		Name: "code",
		Hash: "------",
	}

	manifest := Manifest{
		Wasm:         []Wasm{wasm},
		Config:       make(map[string]string),
		AllowedHosts: []string{},
		AllowedPaths: make(map[string]string),
	}

	ctx := context.Background()
	config := wasiPluginConfig()

	_, err := NewPlugin(ctx, manifest, config, []HostFunction{})

	assert.NotNil(t, err, "Plugin must fail")
}

func TestFunctionExsits(t *testing.T) {
	manifest := manifest("alloc.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		assert.True(t, plugin.FunctionExists("run_test"))
		assert.False(t, plugin.FunctionExists("i_dont_exist"))
	}
}

func TestFailOnUnknownFunction(t *testing.T) {
	manifest := manifest("alloc.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		_, _, err := plugin.Call("i_dont_exist", []byte{})
		assert.NotNil(t, err, "Call to unknwon function must fail")
	}
}

func TestCallFunction(t *testing.T) {
	manifest := manifest("count_vowels.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		cases := map[string]int{
			"hello world": 3,
			"aaaaaa":      6,
			"":            0,
			"bbbbbbb":     0,
		}

		for input, expected := range cases {
			exit, output, err := plugin.Call("count_vowels", []byte(input))

			if assertCall(t, err, exit) {
				var actual map[string]int
				json.Unmarshal(output, &actual)

				assert.Equal(t, expected, actual["count"], "'%s' contains %v vowels", input, expected)
			}
		}
	}
}

func TestClosePlugin(t *testing.T) {
	manifest := manifest("alloc.wasm")

	if plugin, ok := plugin(t, manifest); ok {

		exit, _, err := plugin.Call("run_test", []byte{})
		assertCall(t, err, exit)

		plugin.Close()

		_, _, err = plugin.Call("run_test", []byte{})
		assert.NotNil(t, err, "Call must fail after plugin was closed")
	}
}

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

			assert.Equal(t, expected, actual, fmt.Sprintf("exit must be %v. config: '%v'", expected, config))
		}
	}
}

func TestHost_simple(t *testing.T) {
	manifest := manifest("host.wasm")

	mult := HostFunction{
		Name:      "mult",
		Namespace: "env",
		Callback: func(ctx context.Context, plugin *CurrentPlugin, userData interface{}, stack []uint64) {
			a := api.DecodeI32(stack[0])
			b := api.DecodeI32(stack[1])

			stack[0] = api.EncodeI32(a * b)
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

func TestHost_memory(t *testing.T) {
	manifest := manifest("host_memory.wasm")

	mult := HostFunction{
		Name:      "to_upper",
		Namespace: "host",
		Callback: func(ctx context.Context, plugin *CurrentPlugin, userData interface{}, stack []uint64) {
			offset := stack[0]
			buffer, err := plugin.ReadBytes(offset)
			if err != nil {
				panic(err)
			}

			result := bytes.ToUpper(buffer)
			plugin.Logf(Debug, "Result: %s", result)

			plugin.Free(offset)

			offset, err = plugin.WriteBytes(result)
			if err != nil {
				panic(err)
			}

			stack[0] = offset
		},
		Params:  []api.ValueType{api.ValueTypeI64},
		Results: []api.ValueType{api.ValueTypeI64},
	}

	if plugin, ok := plugin(t, manifest, mult); ok {
		defer plugin.Close()

		exit, output, err := plugin.Call("run_test", []byte("Frodo"))

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "HELLO FRODO!"

			assert.Equal(t, expected, actual)
		}
	}
}

func TestHost_multiple(t *testing.T) {
	manifest := manifest("host_multiple.wasm")

	config := PluginConfig{
		ModuleConfig: wazero.NewModuleConfig().WithSysWalltime(),
		EnableWasi:   true,
	}

	green_message := HostFunction{
		Name:      "hostGreenMessage",
		Namespace: "env",
		Callback: func(ctx context.Context, plugin *CurrentPlugin, userData interface{}, stack []uint64) {
			offset := stack[0]
			input, err := plugin.ReadString(offset)

			if err != nil {
				fmt.Println("🥵", err.Error())
				panic(err)
			}

			message := "🟢:" + string(input)
			offset, err = plugin.WriteString(message)

			if err != nil {
				fmt.Println("🥵", err.Error())
				panic(err)
			}

			stack[0] = offset
		},
		Params:  []api.ValueType{api.ValueTypeI64},
		Results: []api.ValueType{api.ValueTypeI64},
	}

	purple_message := HostFunction{
		Name:      "hostPurpleMessage",
		Namespace: "env",
		Callback: func(ctx context.Context, plugin *CurrentPlugin, userData interface{}, stack []uint64) {
			offset := stack[0]
			input, err := plugin.ReadString(offset)

			if err != nil {
				fmt.Println("🥵", err.Error())
				panic(err)
			}

			message := "🟣:" + string(input)
			offset, err = plugin.WriteString(message)

			if err != nil {
				fmt.Println("🥵", err.Error())
				panic(err)
			}

			stack[0] = offset
		},
		Params:  []api.ValueType{api.ValueTypeI64},
		Results: []api.ValueType{api.ValueTypeI64},
	}

	hostFunctions := []HostFunction{
		purple_message,
		green_message,
	}

	ctx := context.Background()
	pluginInst, err := NewPlugin(ctx, manifest, config, hostFunctions)

	if err != nil {
		panic(err)
	}

	_, res, err := pluginInst.Call(
		"say_green",
		[]byte("John Doe"),
	)
	assert.Equal(t, "🟢:🫱 Hey from say_green John Doe", string(res))

	_, res, err = pluginInst.Call(
		"say_purple",
		[]byte("Jane Doe"),
	)
	assert.Equal(t, "🟣:👋 Hello from say_purple Jane Doe", string(res))
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

func TestMultipleCallsOutput(t *testing.T) {
	manifest := manifest("count_vowels.wasm")

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, output1, err := plugin.Call("count_vowels", []byte("aaa"))

		if !assertCall(t, err, exit) {
			return
		}

		exit, output2, err := plugin.Call("count_vowels", []byte("bbb"))

		if !assertCall(t, err, exit) {
			return
		}

		assert.Equal(t, `{"count": 3}`, string(output1))
		assert.Equal(t, `{"count": 0}`, string(output2))
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
