package extism

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	observe "github.com/dylibso/observe-sdk/go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/sys"
)

type PluginCtxKey string
type InputOffsetKey string

//go:embed extism-runtime.wasm
var extismRuntimeWasm []byte

//go:embed extism-runtime.wasm.version
var extismRuntimeWasmVersion string

func RuntimeVersion() string {
	return extismRuntimeWasmVersion
}

// Runtime represents the Extism plugin's runtime environment, including the underlying Wazero runtime and modules.
type Runtime struct {
	Wazero  wazero.Runtime
	Extism  api.Module
	Env     api.Module
	hasWasi bool
}

// PluginInstanceConfig contains configuration options for the Extism plugin.
type PluginInstanceConfig struct {
	ModuleConfig wazero.ModuleConfig
}

// HttpRequest represents an HTTP request to be made by the plugin.
type HttpRequest struct {
	Url     string
	Headers map[string]string
	Method  string
}

// LogLevel defines different log levels.
type LogLevel int32

const (
	logLevelUnset LogLevel = iota // unexporting this intentionally so its only ever the default
	LogLevelTrace
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError

	LogLevelOff LogLevel = math.MaxInt32
)

func (l LogLevel) ExtismCompat() int32 {
	switch l {
	case LogLevelTrace:
		return 0
	case LogLevelDebug:
		return 1
	case LogLevelInfo:
		return 2
	case LogLevelWarn:
		return 3
	case LogLevelError:
		return 4
	default:
		return int32(LogLevelOff)
	}
}

func (l LogLevel) String() string {
	s := ""
	switch l {
	case LogLevelTrace:
		s = "TRACE"
	case LogLevelDebug:
		s = "DEBUG"
	case LogLevelInfo:
		s = "INFO"
	case LogLevelWarn:
		s = "WARN"
	case LogLevelError:
		s = "ERROR"
	default:
		s = "OFF"
	}
	return s
}

// PluginInstance is used to call WASM functions
type PluginInstance struct {
	close  []func(ctx context.Context) error
	extism api.Module

	//Runtime *Runtime
	//Main    Module
	module  api.Module
	Timeout time.Duration
	Config  map[string]string
	// NOTE: maybe we can have some nice methods for getting/setting vars
	Var                  map[string][]byte
	AllowedHosts         []string
	AllowedPaths         map[string]string
	LastStatusCode       int
	MaxHttpResponseBytes int64
	MaxVarBytes          int64
	log                  func(LogLevel, string)
	hasWasi              bool
	guestRuntime         guestRuntime
	Adapter              *observe.AdapterBase
	traceCtx             *observe.TraceCtx
}

func logStd(level LogLevel, message string) {
	log.Print(message)
}

func (p *PluginInstance) Module() *Module {
	return &Module{inner: p.module}
}

// SetLogger sets a custom logging callback
func (p *PluginInstance) SetLogger(logger func(LogLevel, string)) {
	p.log = logger
}

func (p *PluginInstance) Log(level LogLevel, message string) {
	minimumLevel := LogLevel(pluginLogLevel.Load())

	// If the global log level hasn't been set, use LogLevelOff as default
	if minimumLevel == logLevelUnset {
		minimumLevel = LogLevelOff
	}

	if level >= minimumLevel {
		p.log(level, message)
	}
}

func (p *PluginInstance) Logf(level LogLevel, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	p.Log(level, message)
}

// Wasm is an interface that represents different ways of providing WebAssembly data.
type Wasm interface {
	ToWasmData(ctx context.Context) (WasmData, error)
}

// WasmData represents in-memory WebAssembly data, including its content, hash, and name.
type WasmData struct {
	Data []byte `json:"data"`
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

// WasmFile represents WebAssembly data that needs to be loaded from a file.
type WasmFile struct {
	Path string `json:"path"`
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

// WasmUrl represents WebAssembly data that needs to be fetched from a URL.
type WasmUrl struct {
	Url     string            `json:"url"`
	Hash    string            `json:"hash,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Name    string            `json:"name,omitempty"`
	Method  string            `json:"method,omitempty"`
}

type concreteWasm struct {
	Data    []byte            `json:"data,omitempty"`
	Path    string            `json:"path,omitempty"`
	Url     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Method  string            `json:"method,omitempty"`
	Hash    string            `json:"hash,omitempty"`
	Name    string            `json:"name,omitempty"`
}

func (d WasmData) ToWasmData(ctx context.Context) (WasmData, error) {
	return d, nil
}

func (f WasmFile) ToWasmData(ctx context.Context) (WasmData, error) {
	select {
	case <-ctx.Done():
		return WasmData{}, ctx.Err()
	default:
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return WasmData{}, err
		}

		return WasmData{
			Data: data,
			Hash: f.Hash,
			Name: f.Name,
		}, nil
	}
}

func (u WasmUrl) ToWasmData(ctx context.Context) (WasmData, error) {
	client := http.DefaultClient

	req, err := http.NewRequestWithContext(ctx, u.Method, u.Url, nil)
	if err != nil {
		return WasmData{}, err
	}

	for key, value := range u.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return WasmData{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return WasmData{}, errors.New("failed to fetch Wasm data from URL")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return WasmData{}, err
	}

	return WasmData{
		Data: data,
		Hash: u.Hash,
		Name: u.Name,
	}, nil
}

type ManifestMemory struct {
	MaxPages             uint32 `json:"max_pages,omitempty"`
	MaxHttpResponseBytes int64  `json:"max_http_response_bytes,omitempty"`
	MaxVarBytes          int64  `json:"max_var_bytes,omitempty"`
}

// Manifest represents the plugin's manifest, including Wasm modules and configuration.
// See https://extism.org/docs/concepts/manifest for schema.
type Manifest struct {
	Wasm         []Wasm            `json:"wasm"`
	Memory       *ManifestMemory   `json:"memory,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	AllowedHosts []string          `json:"allowed_hosts,omitempty"`
	AllowedPaths map[string]string `json:"allowed_paths,omitempty"`
	Timeout      uint64            `json:"timeout_ms,omitempty"`
}

type concreteManifest struct {
	Wasm   []concreteWasm `json:"wasm"`
	Memory *struct {
		MaxPages             uint32 `json:"max_pages,omitempty"`
		MaxHttpResponseBytes *int64 `json:"max_http_response_bytes,omitempty"`
		MaxVarBytes          *int64 `json:"max_var_bytes,omitempty"`
	} `json:"memory,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	AllowedHosts []string          `json:"allowed_hosts,omitempty"`
	AllowedPaths map[string]string `json:"allowed_paths,omitempty"`
	Timeout      uint64            `json:"timeout_ms,omitempty"`
}

func (m *Manifest) UnmarshalJSON(data []byte) error {
	tmp := concreteManifest{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	m.Memory = &ManifestMemory{}
	if tmp.Memory != nil {
		m.Memory.MaxPages = tmp.Memory.MaxPages
		if tmp.Memory.MaxHttpResponseBytes != nil {
			m.Memory.MaxHttpResponseBytes = *tmp.Memory.MaxHttpResponseBytes
		} else {
			m.Memory.MaxHttpResponseBytes = -1
		}

		if tmp.Memory.MaxVarBytes != nil {
			m.Memory.MaxVarBytes = *tmp.Memory.MaxVarBytes
		} else {
			m.Memory.MaxVarBytes = -1
		}
	} else {
		m.Memory.MaxPages = 0
		m.Memory.MaxHttpResponseBytes = -1
		m.Memory.MaxVarBytes = -1
	}
	m.Config = tmp.Config
	m.AllowedHosts = tmp.AllowedHosts
	m.AllowedPaths = tmp.AllowedPaths
	m.Timeout = tmp.Timeout
	if m.Wasm == nil {
		m.Wasm = []Wasm{}
	}
	for _, w := range tmp.Wasm {
		if len(w.Data) > 0 {
			m.Wasm = append(m.Wasm, WasmData{Data: w.Data, Hash: w.Hash, Name: w.Name})
		} else if len(w.Path) > 0 {
			m.Wasm = append(m.Wasm, WasmFile{Path: w.Path, Hash: w.Hash, Name: w.Name})
		} else if len(w.Url) > 0 {
			m.Wasm = append(m.Wasm, WasmUrl{
				Url:     w.Url,
				Headers: w.Headers,
				Method:  w.Method,
				Hash:    w.Hash,
				Name:    w.Name,
			})
		} else {
			return errors.New("invalid Wasm entry")
		}
	}
	return nil
}

// Close closes the plugin by freeing the underlying resources.
func (p *PluginInstance) Close(ctx context.Context) error {
	return p.CloseWithContext(ctx)
}

// CloseWithContext closes the plugin by freeing the underlying resources.
func (p *PluginInstance) CloseWithContext(ctx context.Context) error {
	for _, fn := range p.close {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

// add an atomic global to store the plugin runtime-wide log level
var pluginLogLevel = atomic.Int32{}

// SetPluginLogLevel sets the log level for the plugin
func SetLogLevel(level LogLevel) {
	pluginLogLevel.Store(int32(level))
}

// NewPlugin creates a new Extism plugin with the given manifest, configuration, and host functions.
// The returned plugin can be used to call WebAssembly functions and interact with the plugin.
//func _NewPlugin(
//	ctx context.Context,
//	manifest Manifest,
//	config PluginInstanceConfig,
//	functions []HostFunction) (*PluginInstance, error) {
//	var rconfig wazero.RuntimeConfig
//	if config.RuntimeConfig == nil {
//		rconfig = wazero.NewRuntimeConfig()
//	} else {
//		rconfig = config.RuntimeConfig
//	}
//
//	// Make sure function calls are cancelled if the context is cancelled
//	if manifest.Timeout > 0 {
//		rconfig = rconfig.WithCloseOnContextDone(true)
//	}
//
//	if manifest.Memory != nil {
//		if manifest.Memory.MaxPages > 0 {
//			rconfig = rconfig.WithMemoryLimitPages(manifest.Memory.MaxPages)
//		}
//	}
//
//	rt := wazero.NewRuntimeWithConfig(ctx, rconfig)
//
//	extism, err := rt.InstantiateWithConfig(ctx, extismRuntimeWasm, wazero.NewModuleConfig().WithName("extism"))
//	if err != nil {
//		return nil, err
//	}
//
//	hostModules := make(map[string][]HostFunction, 0)
//	for _, f := range functions {
//		hostModules[f.Namespace] = append(hostModules[f.Namespace], f)
//	}
//
//	env, err := buildEnvModule(ctx, rt, extism)
//	if err != nil {
//		return nil, err
//	}
//
//	c := Runtime{
//		Wazero: rt,
//		Extism: extism,
//		Env:    env,
//	}
//
//	if config.EnableWasi {
//		wasi_snapshot_preview1.MustInstantiate(ctx, c.Wazero)
//
//		c.hasWasi = true
//	}
//
//	for name, funcs := range hostModules {
//		_, err := buildHostModule(ctx, c.Wazero, name, funcs)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	count := len(manifest.Wasm)
//	if count == 0 {
//		return nil, fmt.Errorf("manifest can't be empty")
//	}
//
//	modules := map[string]Module{}
//
//	// NOTE: this is only necessary for guest modules because
//	// host modules have the same access privileges as the host itself
//	fs := wazero.NewFSConfig()
//
//	for host, guest := range manifest.AllowedPaths {
//		if strings.HasPrefix(host, "ro:") {
//			trimmed := strings.TrimPrefix(host, "ro:")
//			fs = fs.WithReadOnlyDirMount(trimmed, guest)
//		} else {
//			fs = fs.WithDirMount(host, guest)
//		}
//	}
//
//	moduleConfig := config.ModuleConfig
//	if moduleConfig == nil {
//		moduleConfig = wazero.NewModuleConfig()
//	}
//
//	// NOTE: we don't want wazero to call the start function, we will initialize
//	// the guest runtime manually.
//	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
//	moduleConfig = moduleConfig.WithStartFunctions().WithFSConfig(fs)
//
//	_, wasiOutput := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT")
//	if c.hasWasi && wasiOutput {
//		moduleConfig = moduleConfig.WithStderr(os.Stderr).WithStdout(os.Stdout)
//	}
//
//	// Try to find the main module:
//	//  - There is always one main module
//	//  - If a Wasm value has the Name field set to "main" then use that module
//	//  - If there is only one module in the manifest then that is the main module by default
//	//  - Otherwise the last module listed is the main module
//
//	var trace *observe.traceCtx
//	for i, wasm := range manifest.Wasm {
//		data, err := wasm.ToWasmData(ctx)
//		if err != nil {
//			return nil, err
//		}
//
//		_, mainExists := modules["main"]
//		if data.Name == "" || i == len(manifest.Wasm)-1 && !mainExists {
//			data.Name = "main"
//		}
//
//		if data.Name == "main" && config.ObserveAdapter != nil {
//			trace, err = config.ObserveAdapter.NewTraceCtx(ctx, c.Wazero, data.Data, config.ObserveOptions)
//			if err != nil {
//				return nil, fmt.Errorf("failed to initialize Observe Adapter: %v", err)
//			}
//
//			trace.Finish()
//		}
//
//		_, okh := hostModules[data.Name]
//		_, okm := modules[data.Name]
//
//		if data.Name == "extism:host/env" || okh || okm {
//			return nil, fmt.Errorf("module name collision: '%s'", data.Name)
//		}
//
//		if data.Hash != "" {
//			calculatedHash := calculateHash(data.Data)
//			if data.Hash != calculatedHash {
//				return nil, fmt.Errorf("hash mismatch for module '%s'", data.Name)
//			}
//		}
//
//		m, err := c.Wazero.InstantiateWithConfig(ctx, data.Data, moduleConfig.WithName(data.Name))
//		if err != nil {
//			return nil, err
//		}
//
//		modules[data.Name] = Module{inner: m}
//	}
//
//	httpMax := int64(1024 * 1024 * 50)
//	if manifest.Memory != nil && manifest.Memory.MaxHttpResponseBytes >= 0 {
//		httpMax = int64(manifest.Memory.MaxHttpResponseBytes)
//	}
//
//	varMax := int64(1024 * 1024)
//	if manifest.Memory != nil && manifest.Memory.MaxVarBytes >= 0 {
//		varMax = int64(manifest.Memory.MaxVarBytes)
//	}
//	for _, m := range modules {
//		if m.inner.Name() == "main" {
//			p := &PluginInstance{
//				Runtime:              &c,
//				Modules:              modules,
//				Main:                 m,
//				Config:               manifest.Config,
//				Var:                  map[string][]byte{},
//				AllowedHosts:         manifest.AllowedHosts,
//				AllowedPaths:         manifest.AllowedPaths,
//				LastStatusCode:       0,
//				Timeout:              time.Duration(manifest.Timeout) * time.Millisecond,
//				MaxHttpResponseBytes: httpMax,
//				MaxVarBytes:          varMax,
//				log:                  logStd,
//				Adapter:              config.ObserveAdapter,
//				traceCtx:             trace,
//			}
//
//			p.guestRuntime = detectGuestRuntime(ctx, p)
//			return p, nil
//		}
//	}
//
//	return nil, errors.New("no main module found")
//}

// SetInput sets the input data for the plugin to be used in the next WebAssembly function call.
func (p *PluginInstance) SetInput(data []byte) (uint64, error) {
	return p.SetInputWithContext(context.Background(), data)
}

// SetInputWithContext sets the input data for the plugin to be used in the next WebAssembly function call.
func (p *PluginInstance) SetInputWithContext(ctx context.Context, data []byte) (uint64, error) {
	_, err := p.extism.ExportedFunction("reset").Call(ctx)
	if err != nil {
		fmt.Println(err)
		return 0, errors.New("reset")
	}

	ptr, err := p.extism.ExportedFunction("alloc").Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, err
	}
	p.Memory().Write(uint32(ptr[0]), data)
	p.extism.ExportedFunction("input_set").Call(ctx, ptr[0], uint64(len(data)))
	return ptr[0], nil
}

// GetOutput retrieves the output data from the last WebAssembly function call.
func (p *PluginInstance) GetOutput() ([]byte, error) {
	return p.GetOutputWithContext(context.Background())
}

// GetOutputWithContext retrieves the output data from the last WebAssembly function call.
func (p *PluginInstance) GetOutputWithContext(ctx context.Context) ([]byte, error) {
	outputOffs, err := p.extism.ExportedFunction("output_offset").Call(ctx)
	if err != nil {
		return []byte{}, err
	}

	outputLen, err := p.extism.ExportedFunction("output_length").Call(ctx)
	if err != nil {
		return []byte{}, err
	}
	mem, _ := p.Memory().Read(uint32(outputOffs[0]), uint32(outputLen[0]))

	// Make sure output is copied, because `Read` returns a write-through view
	buffer := make([]byte, len(mem))
	copy(buffer, mem)

	return buffer, nil
}

// Memory returns the plugin's WebAssembly memory interface.
func (p *PluginInstance) Memory() api.Memory {
	return p.extism.ExportedMemory("memory")
}

// GetError retrieves the error message from the last WebAssembly function call, if any.
func (p *PluginInstance) GetError() string {
	return p.GetErrorWithContext(context.Background())
}

// GetErrorWithContext retrieves the error message from the last WebAssembly function call.
func (p *PluginInstance) GetErrorWithContext(ctx context.Context) string {
	errOffs, err := p.extism.ExportedFunction("error_get").Call(ctx)
	if err != nil {
		return ""
	}

	if errOffs[0] == 0 {
		return ""
	}

	errLen, err := p.extism.ExportedFunction("length").Call(ctx, errOffs[0])
	if err != nil {
		return ""
	}

	mem, _ := p.Memory().Read(uint32(errOffs[0]), uint32(errLen[0]))
	return string(mem)
}

// FunctionExists returns true when the named function is present in the plugin's main Module
func (p *PluginInstance) FunctionExists(name string) bool {
	return p.module.ExportedFunction(name) != nil
}

// Call a function by name with the given input, returning the output
func (p *PluginInstance) Call(name string, data []byte) (uint32, []byte, error) {
	return p.CallWithContext(context.Background(), name, data)
}

// Call a function by name with the given input and context, returning the output
func (p *PluginInstance) CallWithContext(ctx context.Context, name string, data []byte) (uint32, []byte, error) {
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}

	ctx = context.WithValue(ctx, PluginCtxKey("plugin"), p)

	intputOffset, err := p.SetInput(data)
	if err != nil {
		return 1, []byte{}, err
	}

	ctx = context.WithValue(ctx, InputOffsetKey("inputOffset"), intputOffset)

	var f = p.module.ExportedFunction(name)

	if f == nil {
		return 1, []byte{}, fmt.Errorf("unknown function: %s", name)
	} else if n := len(f.Definition().ResultTypes()); n > 1 {
		return 1, []byte{}, fmt.Errorf("function %s has %v results, expected 0 or 1", name, n)
	}

	var isStart = name == "_start"
	if p.guestRuntime.init != nil && !isStart && !p.guestRuntime.initialized {
		err := p.guestRuntime.init(ctx)
		if err != nil {
			return 1, []byte{}, fmt.Errorf("failed to initialize runtime: %v", err)
		}
		p.guestRuntime.initialized = true
	}

	p.Logf(LogLevelDebug, "Calling function : %v", name)

	res, err := f.Call(ctx)

	if p.traceCtx != nil {
		defer p.traceCtx.Finish()
	}

	// Try to extact WASI exit code
	if exitErr, ok := err.(*sys.ExitError); ok {
		exitCode := exitErr.ExitCode()

		if exitCode == 0 {
			// It's possible for the function to return 0 as an error code, even
			// if the module is closed.
			if p.module.IsClosed() {
				return 0, nil, fmt.Errorf("module is closed")
			}
			err = nil
		}

		if len(res) == 0 {
			res = []uint64{api.EncodeU32(exitCode)}
		}
	}

	var rc uint32
	if len(res) == 0 {
		// As long as there is no error, we assume the call has succeeded
		if err == nil {
			rc = 0
		} else {
			rc = 1
		}
	} else {
		rc = api.DecodeU32(res[0])
	}

	if err != nil {
		return rc, []byte{}, err
	}

	if rc != 0 {
		errMsg := p.GetError()
		if errMsg == "" {
			errMsg = "encountered an unknown error in call to Extism p function " + name
		}
		return rc, []byte{}, errors.New(errMsg)
	}

	output, err := p.GetOutput()
	if err != nil {
		return rc, []byte{}, fmt.Errorf("failed to get output: %v", err)
	}

	return rc, output, nil
}

func calculateHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
