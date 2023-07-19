package extism

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed extism-runtime.wasm
var extismRuntimeWasm []byte

type Runtime struct {
	Wazero wazero.Runtime
	Extism api.Module
	ctx    context.Context
}

type Plugin struct {
	Runtime *Runtime
	Modules []api.Module
	Main    api.Module
	Timeout uint
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
	Timeout      uint              `json:"timeout_ms,omitempty"`
}

func NewRuntime(ctx context.Context, rconfig ...wazero.RuntimeConfig) (Runtime, error) {
	var config wazero.RuntimeConfig
	if len(rconfig) == 0 {
		config = wazero.NewRuntimeConfig()
	} else {
		config = rconfig[0]
	}
	rt := wazero.NewRuntimeWithConfig(ctx, config.WithCloseOnContextDone(true))
	ext, err := rt.InstantiateWithConfig(ctx, extismRuntimeWasm, wazero.NewModuleConfig().WithName("env"))
	if err != nil {
		return Runtime{}, err
	}

	return Runtime{
		Wazero: rt,
		Extism: ext,
		ctx:    ctx,
	}, nil
}

func (c *Runtime) Close() error {
	return c.Wazero.Close(c.ctx)
}

func (c Runtime) WithWasi() Runtime {
	wasi_snapshot_preview1.MustInstantiate(c.ctx, c.Wazero)
	return c
}

func (c *Runtime) NewPlugin(manifest Manifest, config wazero.ModuleConfig) (Plugin, error) {
	count := len(manifest.Wasm)
	if count == 0 {
		return Plugin{}, fmt.Errorf("Manifest can't be empty.")
	}

	modules := make([]api.Module, count)

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

		m, err := c.Wazero.InstantiateWithConfig(c.ctx, data.Data, config.WithStartFunctions().WithName(data.Name))
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
			return Plugin{Runtime: c, Modules: modules, Main: m}, nil
		}
	}

	panic("couldn't find a main module")
}

func (plugin *Plugin) SetInput(data []byte) error {
	plugin.Runtime.Extism.ExportedFunction("extism_reset").Call(plugin.Runtime.ctx, uint64(len(data)))
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

func (plugin *Plugin) Call(name string, data []byte) (int32, []byte, error) {
	ctx := plugin.Runtime.ctx

	if plugin.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(plugin.Runtime.ctx, time.Duration(plugin.Timeout))
		defer cancel()
	}

	if err := plugin.SetInput(data); err != nil {
		return -1, []byte{}, err
	}

	var f = plugin.Main.ExportedFunction(name)

	if f == nil {
		return -1, []byte{}, errors.New(fmt.Sprintf("Unknown function: %s", name))
	}
	res, err := f.Call(ctx)
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
