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
	"net/http"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

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

// PluginConfig contains configuration options for the Extism plugin.
type PluginConfig struct {
	ModuleConfig  wazero.ModuleConfig
	RuntimeConfig wazero.RuntimeConfig
	EnableWasi    bool
	LogLevel      LogLevel
}

// HttpRequest represents an HTTP request to be made by the plugin.
type HttpRequest struct {
	Url     string
	Headers map[string]string
	Method  string
}

// LogLevel defines different log levels.
type LogLevel uint8

const (
	logLevelUnset LogLevel = iota // unexporting this intentionally so its only ever the default
	LogLevelOff
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

func (l LogLevel) String() string {
	s := ""
	switch l {
	case LogLevelError:
		s = "ERROR"
	case LogLevelWarn:
		s = "WARN"
	case LogLevelInfo:
		s = "INFO"
	case LogLevelDebug:
		s = "DEBUG"
	case LogLevelTrace:
		s = "TRACE"
	}
	return s
}

// Plugin is used to call WASM functions
type Plugin struct {
	Runtime *Runtime
	Modules map[string]api.Module
	Main    api.Module
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
	logLevel             LogLevel
	guestRuntime         guestRuntime
}

func logStd(level LogLevel, message string) {
	log.Print(message)
}

// SetLogger sets a custom logging callback
func (p *Plugin) SetLogger(logger func(LogLevel, string)) {
	p.log = logger
}

// SetLogLevel sets the minim logging level, applies to custom logging callbacks too
func (p *Plugin) SetLogLevel(level LogLevel) {
	p.logLevel = level
}

func (p *Plugin) Log(level LogLevel, message string) {
	if level > p.logLevel {
		return
	}

	p.log(level, message)
}

func (p *Plugin) Logf(level LogLevel, format string, args ...any) {
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
			return errors.New("Invalid Wasm entry")
		}
	}
	return nil
}

// Close closes the plugin by freeing the underlying resources.
func (p *Plugin) Close() error {
	return p.CloseWithContext(context.Background())
}

// CloseWithContext closes the plugin by freeing the underlying resources.
func (p *Plugin) CloseWithContext(ctx context.Context) error {
	return p.Runtime.Wazero.Close(ctx)
}

// NewPlugin creates a new Extism plugin with the given manifest, configuration, and host functions.
// The returned plugin can be used to call WebAssembly functions and interact with the plugin.
func NewPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
	functions []HostFunction) (*Plugin, error) {
	var rconfig wazero.RuntimeConfig
	if config.RuntimeConfig == nil {
		rconfig = wazero.NewRuntimeConfig()
	} else {
		rconfig = config.RuntimeConfig
	}

	// Make sure function calls are cancelled if the context is cancelled
	if manifest.Timeout > 0 {
		rconfig = rconfig.WithCloseOnContextDone(true)
	}

	if manifest.Memory != nil {
		if manifest.Memory.MaxPages > 0 {
			rconfig = rconfig.WithMemoryLimitPages(manifest.Memory.MaxPages)
		}
	}

	rt := wazero.NewRuntimeWithConfig(ctx, rconfig)

	extism, err := rt.InstantiateWithConfig(ctx, extismRuntimeWasm, wazero.NewModuleConfig().WithName("extism"))
	if err != nil {
		return nil, err
	}

	hostModules := make(map[string][]HostFunction, 0)
	for _, f := range functions {
		hostModules[f.Namespace] = append(hostModules[f.Namespace], f)
	}

	env, err := buildEnvModule(ctx, rt, extism)
	if err != nil {
		return nil, err
	}

	c := Runtime{
		Wazero: rt,
		Extism: extism,
		Env:    env,
	}

	if config.EnableWasi {
		wasi_snapshot_preview1.MustInstantiate(ctx, c.Wazero)

		c.hasWasi = true
	}

	for name, funcs := range hostModules {
		_, err := buildHostModule(ctx, c.Wazero, name, funcs)
		if err != nil {
			return nil, err
		}
	}

	count := len(manifest.Wasm)
	if count == 0 {
		return nil, fmt.Errorf("Manifest can't be empty.")
	}

	modules := map[string]api.Module{}

	// NOTE: this is only necessary for guest modules because
	// host modules have the same access privileges as the host itself
	fs := wazero.NewFSConfig()

	for host, guest := range manifest.AllowedPaths {
		// TODO: wazero supports read-only mounting, do we want to support that too?
		fs = fs.WithDirMount(host, guest)
	}

	moduleConfig := config.ModuleConfig
	if moduleConfig == nil {
		moduleConfig = wazero.NewModuleConfig()
	}

	// NOTE: we don't want wazero to call the start function, we will initialize
	// the guest runtime manually.
	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
	moduleConfig = moduleConfig.WithStartFunctions().WithFSConfig(fs)

	_, wasiOutput := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT")
	if c.hasWasi && wasiOutput {
		moduleConfig = moduleConfig.WithStderr(os.Stderr).WithStdout(os.Stdout)
	}

	// Try to find the main module:
	//  - There is always one main module
	//  - If a Wasm value has the Name field set to "main" then use that module
	//  - If there is only one module in the manifest then that is the main module by default
	//  - Otherwise the last module listed is the main module

	for i, wasm := range manifest.Wasm {
		data, err := wasm.ToWasmData(ctx)
		if err != nil {
			return nil, err
		}

		_, mainExists := modules["main"]
		if data.Name == "" || i == len(manifest.Wasm)-1 && !mainExists {
			data.Name = "main"
		}

		_, okh := hostModules[data.Name]
		_, okm := modules[data.Name]

		if data.Name == "extism:host/env" || okh || okm {
			return nil, fmt.Errorf("Module name collision: '%s'", data.Name)
		}

		if data.Hash != "" {
			calculatedHash := calculateHash(data.Data)
			if data.Hash != calculatedHash {
				return nil, fmt.Errorf("Hash mismatch for module '%s'", data.Name)
			}
		}

		m, err := c.Wazero.InstantiateWithConfig(ctx, data.Data, moduleConfig.WithName(data.Name))
		if err != nil {
			return nil, err
		}

		modules[data.Name] = m
	}

	logLevel := LogLevelWarn
	if config.LogLevel != logLevelUnset {
		logLevel = config.LogLevel
	}

	i := 0
	httpMax := int64(1024 * 1024 * 50)
	if manifest.Memory != nil && manifest.Memory.MaxHttpResponseBytes >= 0 {
		httpMax = int64(manifest.Memory.MaxHttpResponseBytes)
	}

	varMax := int64(1024 * 1024)
	if manifest.Memory != nil && manifest.Memory.MaxVarBytes >= 0 {
		varMax = int64(manifest.Memory.MaxVarBytes)
	}
	for _, m := range modules {
		if m.Name() == "main" {
			p := &Plugin{
				Runtime:              &c,
				Modules:              modules,
				Main:                 m,
				Config:               manifest.Config,
				Var:                  map[string][]byte{},
				AllowedHosts:         manifest.AllowedHosts,
				AllowedPaths:         manifest.AllowedPaths,
				LastStatusCode:       0,
				Timeout:              time.Duration(manifest.Timeout) * time.Millisecond,
				MaxHttpResponseBytes: httpMax,
				MaxVarBytes:          varMax,
				log:                  logStd,
				logLevel:             logLevel,
			}

			p.guestRuntime = detectGuestRuntime(ctx, p)
			return p, nil
		}

		i++
	}

	return nil, errors.New("No main module found")
}

// SetInput sets the input data for the plugin to be used in the next WebAssembly function call.
func (plugin *Plugin) SetInput(data []byte) (uint64, error) {
	return plugin.SetInputWithContext(context.Background(), data)
}

// SetInputWithContext sets the input data for the plugin to be used in the next WebAssembly function call.
func (plugin *Plugin) SetInputWithContext(ctx context.Context, data []byte) (uint64, error) {
	_, err := plugin.Runtime.Extism.ExportedFunction("reset").Call(ctx)
	if err != nil {
		fmt.Println(err)
		return 0, errors.New("reset")
	}

	ptr, err := plugin.Runtime.Extism.ExportedFunction("alloc").Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, err
	}
	plugin.Memory().Write(uint32(ptr[0]), data)
	plugin.Runtime.Extism.ExportedFunction("input_set").Call(ctx, ptr[0], uint64(len(data)))
	return ptr[0], nil
}

// GetOutput retrieves the output data from the last WebAssembly function call.
func (plugin *Plugin) GetOutput() ([]byte, error) {
	return plugin.GetOutputWithContext(context.Background())
}

// GetOutputWithContext retrieves the output data from the last WebAssembly function call.
func (plugin *Plugin) GetOutputWithContext(ctx context.Context) ([]byte, error) {
	outputOffs, err := plugin.Runtime.Extism.ExportedFunction("output_offset").Call(ctx)
	if err != nil {
		return []byte{}, err
	}

	outputLen, err := plugin.Runtime.Extism.ExportedFunction("output_length").Call(ctx)
	if err != nil {
		return []byte{}, err
	}
	mem, _ := plugin.Memory().Read(uint32(outputOffs[0]), uint32(outputLen[0]))

	// Make sure output is copied, because `Read` returns a write-through view
	buffer := make([]byte, len(mem))
	copy(buffer, mem)

	return buffer, nil
}

// Memory returns the plugin's WebAssembly memory interface.
func (plugin *Plugin) Memory() api.Memory {
	return plugin.Runtime.Extism.ExportedMemory("memory")
}

// GetError retrieves the error message from the last WebAssembly function call, if any.
func (plugin *Plugin) GetError() string {
	return plugin.GetErrorWithContext(context.Background())
}

// GetErrorWithContext retrieves the error message from the last WebAssembly function call.
func (plugin *Plugin) GetErrorWithContext(ctx context.Context) string {
	errOffs, err := plugin.Runtime.Extism.ExportedFunction("error_get").Call(ctx)
	if err != nil {
		return ""
	}

	if errOffs[0] == 0 {
		return ""
	}

	errLen, err := plugin.Runtime.Extism.ExportedFunction("length").Call(ctx, errOffs[0])
	if err != nil {
		return ""
	}

	mem, _ := plugin.Memory().Read(uint32(errOffs[0]), uint32(errLen[0]))
	return string(mem)
}

// FunctionExists returns true when the named function is present in the plugin's main module
func (plugin *Plugin) FunctionExists(name string) bool {
	return plugin.Main.ExportedFunction(name) != nil
}

// Call a function by name with the given input, returning the output
func (plugin *Plugin) Call(name string, data []byte) (uint32, []byte, error) {
	return plugin.CallWithContext(context.Background(), name, data)
}

// Call a function by name with the given input and context, returning the output
func (plugin *Plugin) CallWithContext(ctx context.Context, name string, data []byte) (uint32, []byte, error) {
	if plugin.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, plugin.Timeout)
		defer cancel()
	}

	ctx = context.WithValue(ctx, "plugin", plugin)

	intputOffset, err := plugin.SetInput(data)
	if err != nil {
		return 1, []byte{}, err
	}

	ctx = context.WithValue(ctx, "inputOffset", intputOffset)

	var f = plugin.Main.ExportedFunction(name)

	if f == nil {
		return 1, []byte{}, errors.New(fmt.Sprintf("Unknown function: %s", name))
	} else if n := len(f.Definition().ResultTypes()); n > 1 {
		return 1, []byte{}, errors.New(fmt.Sprintf("Function %s has %v results, expected 0 or 1", name, n))
	}

	var isStart = name == "_start"
	if plugin.guestRuntime.init != nil && !isStart && !plugin.guestRuntime.initialized {
		err := plugin.guestRuntime.init(ctx)
		if err != nil {
			return 1, []byte{}, errors.New(fmt.Sprintf("failed to initialize runtime: %v", err))
		}
		plugin.guestRuntime.initialized = true
	}

	plugin.Logf(LogLevelDebug, "Calling function : %v", name)

	res, err := f.Call(ctx)

	// Try to extact WASI exit code
	if exitErr, ok := err.(*sys.ExitError); ok {
		exitCode := exitErr.ExitCode()

		if exitCode == 0 {
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
		errMsg := plugin.GetError()
		if errMsg == "" {
			errMsg = "Encountered an unknown error in call to Extism plugin function " + name
		}
		return rc, []byte{}, errors.New(errMsg)
	}

	output, err := plugin.GetOutput()
	if err != nil {
		return rc, []byte{}, fmt.Errorf("Failed to get output: %v", err)
	}

	return rc, output, nil
}

func calculateHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
