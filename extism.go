package extism

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed extism-runtime.wasm
var extismRuntimeWasm []byte

type Runtime struct {
	Wazero  wazero.Runtime
	Extism  api.Module
	Env     api.Module
	ctx     context.Context
	hasWasi bool
}

type PluginConfig struct {
	ModuleConfig  wazero.ModuleConfig
	RuntimeConfig []wazero.RuntimeConfig
	EnableWasi    bool
}

type HttpRequest struct {
	Url     string
	Headers map[string]string
	Method  string
}

type LogLevel uint8

const (
	Off LogLevel = iota
	Error
	Warn
	Info
	Debug
	Trace
)

type Plugin struct {
	Runtime *Runtime
	Modules []api.Module
	Main    api.Module
	Timeout time.Duration
	Config  map[string]string
	// NOTE: maybe we can have some nice methods for getting/setting vars
	Var            map[string][]byte
	AllowedHosts   []string
	AllowedPaths   map[string]string
	LastStatusCode int
	log            func(LogLevel, string)
	logLevel       LogLevel
	guestRuntime   GuestRuntime
}

func logStd(level LogLevel, message string) {
	log.Printf(message)
}

func (p *Plugin) SetLogger(logger func(LogLevel, string)) {
	p.log = logger
}

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

type Wasm interface {
	ToWasmData() (WasmData, error)
}

type WasmData struct {
	Data []byte `json:"data"`
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

type WasmFile struct {
	Path string `json:"path"`
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

type WasmUrl struct {
	Url     string            `json:"url"`
	Hash    string            `json:"hash,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Name    string            `json:"name,omitempty"`
	Method  string            `json:"method,omitempty"`
}

func (d WasmData) ToWasmData() (WasmData, error) {
	return d, nil
}

func (f WasmFile) ToWasmData() (WasmData, error) {
	data, err := ioutil.ReadFile(f.Path)
	if err != nil {
		return WasmData{}, err
	}

	return WasmData{
		Data: data,
		Hash: f.Hash,
		Name: f.Name,
	}, nil
}

func (u WasmUrl) ToWasmData() (WasmData, error) {
	client := http.DefaultClient

	req, err := http.NewRequest(u.Method, u.Url, nil)
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

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return WasmData{}, err
	}

	return WasmData{
		Data: data,
		Hash: u.Hash,
		Name: u.Name,
	}, nil
}

type Manifest struct {
	Wasm   []Wasm `json:"wasm"`
	Memory struct {
		MaxPages uint32 `json:"max_pages,omitempty"`
	} `json:"memory,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	AllowedHosts []string          `json:"allowed_hosts,omitempty"`
	AllowedPaths map[string]string `json:"allowed_paths,omitempty"`
	Timeout      time.Duration     `json:"timeout_ms,omitempty"`
}

func (p *Plugin) Close() error {
	return p.Runtime.Wazero.Close(p.Runtime.ctx)
}

func NewPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
	functions []HostFunction) (Plugin, error) {

	var rconfig wazero.RuntimeConfig
	if len(config.RuntimeConfig) == 0 {
		rconfig = wazero.NewRuntimeConfig()
	} else {
		rconfig = config.RuntimeConfig[0]
	}

	if manifest.Memory.MaxPages > 0 {
		rconfig = rconfig.WithMemoryLimitPages(manifest.Memory.MaxPages)
	}

	rt := wazero.NewRuntimeWithConfig(ctx, rconfig.WithCloseOnContextDone(true))

	extism, err := rt.InstantiateWithConfig(ctx, extismRuntimeWasm, wazero.NewModuleConfig().WithName("extism"))
	if err != nil {
		return Plugin{}, err
	}

	hostModules := make(map[string][]HostFunction, 0)
	for _, f := range functions {
		hostModules[f.Namespace] = append(hostModules[f.Namespace], f)
	}

	env, err := buildEnvModule(ctx, rt, extism, hostModules["env"])
	if err != nil {
		return Plugin{}, err
	}

	c := Runtime{
		Wazero: rt,
		Extism: extism,
		Env:    env,
		ctx:    ctx,
	}

	if config.EnableWasi {
		wasi_snapshot_preview1.MustInstantiate(c.ctx, c.Wazero)

		c.hasWasi = true
	}

	for name, funcs := range hostModules {
		// `env` host functions are handled by `buildEnvModule
		if name == "env" {
			continue
		}

		// TODO: check for colision with other module names
		// TODO: take special care of `env` module host functions
		_, err := buildHostModule(c.ctx, c.Wazero, name, funcs)
		if err != nil {
			return Plugin{}, err
		}
	}

	count := len(manifest.Wasm)
	if count == 0 {
		return Plugin{}, fmt.Errorf("Manifest can't be empty.")
	}

	modules := make([]api.Module, count)

	// NOTE: this is only necessary for guest modules because
	// host modules have the same access privileges as the host itself
	fs := wazero.NewFSConfig()

	for host, guest := range manifest.AllowedPaths {
		// TODO: wazero supports read-only mounting, do we want to support that too?
		fs = fs.WithDirMount(host, guest)
	}

	// NOTE: we don't want wazero to call the start function, we will initialize
	// the guest runtime manually.
	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
	moduleConfig := config.ModuleConfig.WithStartFunctions().WithFSConfig(fs)

	for index, wasm := range manifest.Wasm {
		data, err := wasm.ToWasmData()
		if err != nil {
			return Plugin{}, err
		}

		if data.Hash != "" {
			calculatedHash := calculateHash(data.Data)
			if data.Hash != calculatedHash {
				return Plugin{}, fmt.Errorf("Hash mismatch for module '%s'", data.Name)
			}
		}

		m, err := c.Wazero.InstantiateWithConfig(c.ctx, data.Data, moduleConfig.WithName(data.Name))
		if err != nil {
			return Plugin{}, err
		} else if count > 1 && m.Name() == "" {
			return Plugin{}, fmt.Errorf("Module name can't be empty if manifest contains multiple modules.")
		}

		modules[index] = m
	}

	// Try to find the main module:
	//  - There is always one main module
	//  - If a Wasm value has the Name field set to "main" then use that module
	//  - If there is only one module in the manifest then that is the main module by default
	//  - Otherwise the last module listed is the main module

	for i, m := range modules {
		if m.Name() == "main" || i == len(modules)-1 {
			p := Plugin{
				Runtime:        &c,
				Modules:        modules,
				Main:           m,
				Config:         manifest.Config,
				Var:            map[string][]byte{},
				AllowedHosts:   manifest.AllowedHosts,
				AllowedPaths:   manifest.AllowedPaths,
				LastStatusCode: 0,
				Timeout:        manifest.Timeout,
				log:            logStd,
				logLevel:       Warn}

			p.guestRuntime = guestRuntime(&p, m)

			return p, nil
		}
	}

	return Plugin{}, errors.New("No main module found")
}

func (plugin *Plugin) SetInput(data []byte) error {
	_, err := plugin.Runtime.Extism.ExportedFunction("extism_reset").Call(plugin.Runtime.ctx)
	if err != nil {
		fmt.Println(err)
		return errors.New("reset")
	}
	ptr, err := plugin.Runtime.Extism.ExportedFunction("extism_alloc").Call(plugin.Runtime.ctx, uint64(len(data)))
	if err != nil {
		return err
	}
	plugin.Memory().Write(uint32(ptr[0]), data)
	plugin.Runtime.Extism.ExportedFunction("extism_input_set").Call(plugin.Runtime.ctx, ptr[0], uint64(len(data)))
	return nil
}

func (plugin *Plugin) GetOutput() ([]byte, error) {
	outputOffs, err := plugin.Runtime.Extism.ExportedFunction("extism_output_offset").Call(plugin.Runtime.ctx)
	if err != nil {
		return []byte{}, err
	}

	outputLen, err := plugin.Runtime.Extism.ExportedFunction("extism_output_length").Call(plugin.Runtime.ctx)
	if err != nil {
		return []byte{}, err
	}
	mem, _ := plugin.Memory().Read(uint32(outputOffs[0]), uint32(outputLen[0]))
	return mem, nil
}

func (plugin *Plugin) Memory() api.Memory {
	return plugin.Runtime.Extism.ExportedMemory("memory")
}

func (plugin *Plugin) GetError() string {
	errOffs, err := plugin.Runtime.Extism.ExportedFunction("extism_error_get").Call(plugin.Runtime.ctx)
	if err != nil {
		return ""
	}

	if errOffs[0] == 0 {
		return ""
	}

	errLen, err := plugin.Runtime.Extism.ExportedFunction("extism_length").Call(plugin.Runtime.ctx, errOffs[0])
	if err != nil {
		return ""
	}

	mem, _ := plugin.Memory().Read(uint32(errOffs[0]), uint32(errLen[0]))
	return string(mem)
}

type result struct {
	rc  int32
	err error
}

func (plugin *Plugin) FunctionExists(name string) bool {
	return plugin.Main.ExportedFunction(name) != nil
}

func (plugin *Plugin) Call(name string, data []byte) (int32, []byte, error) {
	ctx := plugin.Runtime.ctx

	if plugin.Timeout > 0 {
		timeout := time.Duration(plugin.Timeout) * time.Millisecond

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(plugin.Runtime.ctx, timeout)
		defer cancel()
	}

	ctx = context.WithValue(ctx, "plugin", plugin)

	if err := plugin.SetInput(data); err != nil {
		return -1, []byte{}, err
	}

	isStart := name == "_start"

	var f = plugin.Main.ExportedFunction(name)

	if f == nil {
		return -1, []byte{}, errors.New(fmt.Sprintf("Unknown function: %s", name))
	}

	if !isStart && plugin.guestRuntime.Type != None {
		err := plugin.guestRuntime.Initialize()
		if err != nil {
			return -1, []byte{}, errors.New(fmt.Sprintf("failed to initialize runtime: %v", err))
		}
	}

	plugin.Logf(Debug, "Calling function : %v", name)

	res, err := f.Call(ctx)

	if !isStart && plugin.guestRuntime.Cleanup != nil {
		err := plugin.guestRuntime.Cleanup()
		if err != nil {
			return -1, []byte{}, errors.New(fmt.Sprintf("failed to cleanup runtime: %v", err))
		}
	}

	var rc int32
	if len(res) == 0 {
		rc = -1
	} else {
		rc = int32(res[0])
	}
	if err != nil {
		return rc, []byte{}, err
	}

	if rc != 0 {
		errMsg := plugin.GetError()
		if errMsg == "" {
			errMsg = "Call failed"
		}
		return rc, []byte{}, errors.New(errMsg)
	}

	output, err := plugin.GetOutput()
	if err != nil {
		return rc, []byte{}, err
	}

	return rc, output, nil

}

func calculateHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
