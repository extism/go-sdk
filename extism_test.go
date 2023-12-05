package extism

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/sys"
)

func TestWasmUrl(t *testing.T) {
	url := "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm"
	wasm := WasmUrl{
		Url:  url,
		Name: "code",
		Hash: "0c1779c48f56f94b3e3624d76f55e38215870c59ccb3d41f6ba8b2bc22f218f5",
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

	mult := NewHostFunctionWithStack(
		"mult",
		func(ctx context.Context, plugin *CurrentPlugin, stack []uint64) {
			a := DecodeI32(stack[0])
			b := DecodeI32(stack[1])

			stack[0] = EncodeI32(a * b)
		},
		[]ValueType{ValueTypePTR, ValueTypePTR},
		[]ValueType{ValueTypePTR},
	)

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

	mult := NewHostFunctionWithStack(
		"to_upper",
		func(ctx context.Context, plugin *CurrentPlugin, stack []uint64) {
			offset := stack[0]
			buffer, err := plugin.ReadBytes(offset)
			if err != nil {
				panic(err)
			}

			result := bytes.ToUpper(buffer)
			plugin.Logf(LogLevelDebug, "Result: %s", result)

			plugin.Free(offset)

			offset, err = plugin.WriteBytes(result)
			if err != nil {
				panic(err)
			}

			stack[0] = offset
		},
		[]ValueType{ValueTypePTR},
		[]ValueType{ValueTypePTR},
	)

	mult.SetNamespace("host")

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

	green_message := NewHostFunctionWithStack(
		"hostGreenMessage",
		func(ctx context.Context, plugin *CurrentPlugin, stack []uint64) {
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
		[]ValueType{ValueTypePTR},
		[]ValueType{ValueTypePTR},
	)

	purple_message := NewHostFunctionWithStack(
		"hostPurpleMessage",
		func(ctx context.Context, plugin *CurrentPlugin, stack []uint64) {
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
		[]ValueType{ValueTypePTR},
		[]ValueType{ValueTypePTR},
	)

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
			switch level {
			case LogLevelInfo:
				assert.Equal(t, fmt.Sprintf("%s", level), "INFO")
			case LogLevelWarn:
				assert.Equal(t, fmt.Sprintf("%s", level), "WARN")
			case LogLevelError:
				assert.Equal(t, fmt.Sprintf("%s", level), "ERROR")
			}
		})

		plugin.SetLogLevel(LogLevelInfo)

		exit, _, err := plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			expected := []LogEntry{
				{message: "this is an info log", level: LogLevelInfo},
				{message: "this is a warning log", level: LogLevelWarn},
				{message: "this is an erorr log", level: LogLevelError}}

			assert.Equal(t, expected, actual)
		}
	}
}

func TestTimeout(t *testing.T) {
	manifest := manifest("sleep.wasm")
	manifest.Timeout = 100            // 100ms
	manifest.Config["duration"] = "3" // sleep for 3 seconds

	config := PluginConfig{
		ModuleConfig: wazero.NewModuleConfig().WithSysWalltime(),
		EnableWasi:   true,
	}

	plugin, err := NewPlugin(context.Background(), manifest, config, []HostFunction{})

	if err != nil {
		t.Errorf("Could not create plugin: %v", err)
	}

	defer plugin.Close()

	exit, _, err := plugin.Call("run_test", []byte{})

	assert.Equal(t, sys.ExitCodeDeadlineExceeded, exit, "Exit code must be `sys.ExitCodeDeadlineExceeded`")
	assert.Equal(t, "module closed with context deadline exceeded", err.Error())
}

func TestCancel(t *testing.T) {
	manifest := manifest("sleep.wasm")
	manifest.Config["duration"] = "3" // sleep for 3 seconds

	ctx, cancel := context.WithCancel(context.Background())
	config := PluginConfig{
		ModuleConfig:  wazero.NewModuleConfig().WithSysWalltime(),
		EnableWasi:    true,
		RuntimeConfig: wazero.NewRuntimeConfig().WithCloseOnContextDone(true),
	}

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

		exit, _, err = plugin.Call("run_test", []byte{})

		if assertCall(t, err, exit) {
			actual := uintFromLEBytes(plugin.Var["a"])
			expected := uint(40)

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

		exit, output2, err := plugin.Call("count_vowels", []byte("bbba"))

		if !assertCall(t, err, exit) {
			return
		}

		assert.Equal(t, `{"count":3,"total":3,"vowels":"aeiouAEIOU"}`, string(output1))
		assert.Equal(t, `{"count":1,"total":4,"vowels":"aeiouAEIOU"}`, string(output2))
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

		plugin.SetLogLevel(LogLevelTrace)
		plugin.Config["greeting"] = "Howdy"

		exit, output, err := plugin.Call("testing", []byte("John"))

		if assertCall(t, err, exit) {
			actual := string(output)
			expected := "Howdy, John"

			assert.Equal(t, expected, actual)

			logs := buf.String()

			assert.Contains(t, logs, "Initialized Haskell language runtime.")
		}
	}
}

func TestJsonManifest(t *testing.T) {
	m := `
	{
		"wasm": [
		  {
			"path": "wasm/sleep.wasm"
		  }
		],
		"memory": {
		  "max_pages": 100
		},
		"config": {
		  "key1": "value1",
		  "key2": "value2",
		  "duration": "3"
		},
		"timeout_ms": 100
	}
	`

	manifest := Manifest{}
	err := manifest.UnmarshalJSON([]byte(m))
	if err != nil {
		t.Error(err)
	}

	if plugin, ok := plugin(t, manifest); ok {
		defer plugin.Close()

		exit, _, err := plugin.Call("run_test", []byte{})

		assert.Equal(t, sys.ExitCodeDeadlineExceeded, exit, "Exit code must be `sys.ExitCodeDeadlineExceeded`")
		assert.Equal(t, "module closed with context deadline exceeded", err.Error())
	}
}

func BenchmarkInitialize(b *testing.B) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)

	b.ResetTimer()
	b.Run("noop", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			manifest := Manifest{Wasm: []Wasm{WasmFile{Path: "wasm/noop.wasm"}}}

			config := PluginConfig{
				EnableWasi:    true,
				ModuleConfig:  wazero.NewModuleConfig(),
				RuntimeConfig: wazero.NewRuntimeConfig(),
			}

			_, err := NewPlugin(ctx, manifest, config, []HostFunction{})
			if err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkInitializeWithCache(b *testing.B) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)

	b.ResetTimer()
	b.Run("noop", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			manifest := Manifest{Wasm: []Wasm{WasmFile{Path: "wasm/noop.wasm"}}}

			config := PluginConfig{
				EnableWasi:    true,
				ModuleConfig:  wazero.NewModuleConfig(),
				RuntimeConfig: wazero.NewRuntimeConfig().WithCompilationCache(cache),
			}

			_, err := NewPlugin(ctx, manifest, config, []HostFunction{})
			if err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkNoop(b *testing.B) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)

	manifest := Manifest{Wasm: []Wasm{WasmFile{Path: "wasm/noop.wasm"}}}

	config := PluginConfig{
		EnableWasi:    true,
		ModuleConfig:  wazero.NewModuleConfig(),
		RuntimeConfig: wazero.NewRuntimeConfig().WithCompilationCache(cache),
	}

	plugin, err := NewPlugin(ctx, manifest, config, []HostFunction{})
	if err != nil {
		panic(err)
	}

	b.ResetTimer()

	b.Run("noop", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _, err := plugin.Call("run_test", []byte{})
			if err != nil {
				panic(err)
			}
		}
	})
}

var (
	Regex2048 = "BYwnOjWhprPmDncp8qpQ5CY4r1RGZuqKLBowmtMCd test ETjLOG685YC4RIjXB0HadNpqYS4M7GPGUVAKRZRC1ibqQqGnuzqX2Hjosm6MKNCp5QifX7Up2phqkFqkjpSu3k59oi6M5YbTMiy4JukVFx2402IlrHU1McK7US0skB1cF0W2ZDpsypNmGJRXRMY0pPsYbw7G2a0xJnhTITXcuF5xJWR1rz5zdGZQbbjZoHZcEnveDFq5kOmCVc test DsJVHTsAlypLI9sVtbTLwmE1DG2C6AgUo3GO1DpCx3jV43oXUxaTVJqZO13AYqvNPbxizYZ5BckZFBbJybY3Vnm20Sm7nXbwZs5N2ugz3EpUQvXwqHdHWzc1T8uKPD5LTDM8UBpVoF test 9G3mWarrp43SvoidITriFhzHmyVWNd6n2LIVocr3pOai4DOlkAn7QDup6z6spMAf8UcI4wbfoSzG0k5Qy1rGBhPaJKJRW2 MC9ma3U3rnjAOBtEUHZ2qfOUpfMNgPlGpvzr4IGNNFf9RFlF7yRUBvRnYxyonIWPPiR1x1wWgxc20o5cW4GU7kytAOuGlpzpykcAxCJLLP6wJegaMhAeb8xBLpuBetNEbfcyyOcJBun5BhmFOmv8 test IvICWx2wlYZ61YDBpPcIpqnMb9MHwT8GroC1YITZBlNGBHMpAe4d2sNZe9d0Wvfbv5mMo30Bm1Pa5S3x38jgu6y0BaqZl9GhlukE9CqPJGUsJZ5suDH19WiOrvz7mXwXhi4lWm1YdwNi0xhVnXITtmKq5rikIS6dul1USgDf3TwyLYpyCG46Xj92PssJmnhPdH1WAnvXY sbs8RaemyqmPggtGNwU2JjuPjdmQRakIusv2WimN7zG8R8Pf1225IAJ2j8aiZBrxnjmrucaYOQCrLm7e2Q5q8 test HOkCEJJGHVLYJtGgHKa1PRQ5qCcsIAUdkW3yRfdulutteLe3We9z9XQvWuTYMLDPpOJqMzDNTGpTYts7AL8pFog1k82XVuMZ6ItccxOBpuzDcahH4wDqCGjak8qPVxmnrGmSsrdUHVz6SrScElMo0nOF8RIpYAVdJr5NxWIK1uzc1iIiZnbUD6uDNmBkmfec6IgK6aqnEZaGLDJXDHSYfzWUOi7y3KNPl0CghL9BId8v4040mCKMfmdthWWLJ2tpWIo1482ghiU5 2qtrzgFgYKfyfr4X6FXzN3hM3bLnuwItQrTCEp3BYz79bCAaQGhicZzqE83Mh2 test IIVID622qlEyVEGuEmNJ5JteEzbpklhTKnVMflzzWyWbZe6kIgeUr9mxWjkJGisvRbZKwfnojeC82M1nHgUa4k46x7Dw7mL3rChORjBxBMYjFeOvCsT6kEo3vPeachLUKdkExJbr9Yei0fKyOFSDlxpFhlRKuwGxXu4jGo4CzKDsVsahqzC9iGw53bHiw0V4Pwmdhzv482s3zU9XLTgQr6GuL1I0kSfh9BkVoK5fFvg1hm7ECrt6p8q3kLVjxte EK9W9q2q9etMaPLymcCRZ0XauMDzJY08JeVvovnT2g5hxE7UGW1 test YRotQUivrrXQnhEw55faznZZBU1ULVs4BfYkIkEfS91NetBhona6zrzDwMsXi0FJjdaiJ25lvetPDaMzUs0l6nfkGkVyU376mFPfPkpBKZR2z2Xwzxndi0SkUnqm8jCa7iq2oSJstTdUXtCK2xTXMIh7tiuPVftit GFYQXXI3vY QFe1xShWJgFAqYguQ8gcxMPSzMlyDaPmMuTPgFZDM0cd test NS3fTggxBa4p5jgS4S0nhae05RkYkXGzuNMXeu6IoR9PFqVFnXcBYD0Ld9otrAiqUuIGYGmAjm3Wx29va2UtIFaRhL02ckRfycz3BGfwqYl3TGtjWdKjmxn1WreRIIq5gkbWJws5VQsov0V2U8pGedj N2RDqWgh2tFiJA9fmytgRgqSnqxIwyBMgY5RnE6CZ0 test Iv4QPiWMu0oG70e4nSNtG13O test "
	Match2048 = "BYwnOjWhprPmDncp8qpQ5CY4r1RGZuqKLBowmtMCd wasm ETjLOG685YC4RIjXB0HadNpqYS4M7GPGUVAKRZRC1ibqQqGnuzqX2Hjosm6MKNCp5QifX7Up2phqkFqkjpSu3k59oi6M5YbTMiy4JukVFx2402IlrHU1McK7US0skB1cF0W2ZDpsypNmGJRXRMY0pPsYbw7G2a0xJnhTITXcuF5xJWR1rz5zdGZQbbjZoHZcEnveDFq5kOmCVc wasm DsJVHTsAlypLI9sVtbTLwmE1DG2C6AgUo3GO1DpCx3jV43oXUxaTVJqZO13AYqvNPbxizYZ5BckZFBbJybY3Vnm20Sm7nXbwZs5N2ugz3EpUQvXwqHdHWzc1T8uKPD5LTDM8UBpVoF wasm 9G3mWarrp43SvoidITriFhzHmyVWNd6n2LIVocr3pOai4DOlkAn7QDup6z6spMAf8UcI4wbfoSzG0k5Qy1rGBhPaJKJRW2 MC9ma3U3rnjAOBtEUHZ2qfOUpfMNgPlGpvzr4IGNNFf9RFlF7yRUBvRnYxyonIWPPiR1x1wWgxc20o5cW4GU7kytAOuGlpzpykcAxCJLLP6wJegaMhAeb8xBLpuBetNEbfcyyOcJBun5BhmFOmv8 wasm IvICWx2wlYZ61YDBpPcIpqnMb9MHwT8GroC1YITZBlNGBHMpAe4d2sNZe9d0Wvfbv5mMo30Bm1Pa5S3x38jgu6y0BaqZl9GhlukE9CqPJGUsJZ5suDH19WiOrvz7mXwXhi4lWm1YdwNi0xhVnXITtmKq5rikIS6dul1USgDf3TwyLYpyCG46Xj92PssJmnhPdH1WAnvXY sbs8RaemyqmPggtGNwU2JjuPjdmQRakIusv2WimN7zG8R8Pf1225IAJ2j8aiZBrxnjmrucaYOQCrLm7e2Q5q8 wasm HOkCEJJGHVLYJtGgHKa1PRQ5qCcsIAUdkW3yRfdulutteLe3We9z9XQvWuTYMLDPpOJqMzDNTGpTYts7AL8pFog1k82XVuMZ6ItccxOBpuzDcahH4wDqCGjak8qPVxmnrGmSsrdUHVz6SrScElMo0nOF8RIpYAVdJr5NxWIK1uzc1iIiZnbUD6uDNmBkmfec6IgK6aqnEZaGLDJXDHSYfzWUOi7y3KNPl0CghL9BId8v4040mCKMfmdthWWLJ2tpWIo1482ghiU5 2qtrzgFgYKfyfr4X6FXzN3hM3bLnuwItQrTCEp3BYz79bCAaQGhicZzqE83Mh2 wasm IIVID622qlEyVEGuEmNJ5JteEzbpklhTKnVMflzzWyWbZe6kIgeUr9mxWjkJGisvRbZKwfnojeC82M1nHgUa4k46x7Dw7mL3rChORjBxBMYjFeOvCsT6kEo3vPeachLUKdkExJbr9Yei0fKyOFSDlxpFhlRKuwGxXu4jGo4CzKDsVsahqzC9iGw53bHiw0V4Pwmdhzv482s3zU9XLTgQr6GuL1I0kSfh9BkVoK5fFvg1hm7ECrt6p8q3kLVjxte EK9W9q2q9etMaPLymcCRZ0XauMDzJY08JeVvovnT2g5hxE7UGW1 wasm YRotQUivrrXQnhEw55faznZZBU1ULVs4BfYkIkEfS91NetBhona6zrzDwMsXi0FJjdaiJ25lvetPDaMzUs0l6nfkGkVyU376mFPfPkpBKZR2z2Xwzxndi0SkUnqm8jCa7iq2oSJstTdUXtCK2xTXMIh7tiuPVftit GFYQXXI3vY QFe1xShWJgFAqYguQ8gcxMPSzMlyDaPmMuTPgFZDM0cd wasm NS3fTggxBa4p5jgS4S0nhae05RkYkXGzuNMXeu6IoR9PFqVFnXcBYD0Ld9otrAiqUuIGYGmAjm3Wx29va2UtIFaRhL02ckRfycz3BGfwqYl3TGtjWdKjmxn1WreRIIq5gkbWJws5VQsov0V2U8pGedj N2RDqWgh2tFiJA9fmytgRgqSnqxIwyBMgY5RnE6CZ0 wasm Iv4QPiWMu0oG70e4nSNtG13O wasm "

	Regex4096 = Regex2048 + Regex2048
	Match4096 = Match2048 + Match2048

	Regex8192 = Regex4096 + Regex4096
	Match8192 = Match4096 + Match4096

	Regex16384 = Regex8192 + Regex8192
	Match16384 = Match8192 + Match8192

	Regex32768 = Regex16384 + Regex16384
	Match32768 = Match16384 + Match16384

	Regex65536 = Regex32768 + Regex32768
	Match65536 = Match32768 + Match32768
)

func BenchmarkReplace(b *testing.B) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)

	manifest := Manifest{Wasm: []Wasm{WasmFile{Path: "wasm/replace.wasm"}}}

	config := PluginConfig{
		EnableWasi:    true,
		ModuleConfig:  wazero.NewModuleConfig(),
		RuntimeConfig: wazero.NewRuntimeConfig().WithCompilationCache(cache),
	}

	plugin, err := NewPlugin(ctx, manifest, config, []HostFunction{})
	if err != nil {
		panic(err)
	}

	b.ResetTimer()

	inputs := map[string][]byte{
		"empty": {},
		"2048":  []byte(Regex2048),
		"4096":  []byte(Regex4096),
		"8192":  []byte(Regex8192),
		"16383": []byte(Regex16384),
		"32768": []byte(Regex32768),
	}

	expected := map[string][]byte{
		"empty": {},
		"2048":  []byte(Match2048),
		"4096":  []byte(Match4096),
		"8192":  []byte(Match8192),
		"16383": []byte(Match16384),
		"32768": []byte(Match32768),
	}

	for k, v := range inputs {
		expected := expected[k]
		b.Run(k, func(b *testing.B) {
			input := v
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, out, err := plugin.Call("run_test", input)
				if err != nil {
					fmt.Println("SOMETHING BAD HAPPENED: ", err)
					panic(err)
				}

				if !equal(out, expected) {
					fmt.Println(string(out))
					panic("invalid regex match")
				}
			}
		})
	}
}

func generateRandomString(length int, seed int64) string {
	rand.Seed(seed)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func wasiPluginConfig() PluginConfig {
	config := PluginConfig{
		ModuleConfig: wazero.NewModuleConfig().WithSysWalltime(),
		EnableWasi:   true,
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
