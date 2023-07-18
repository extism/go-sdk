package extism

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
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
	Module  api.Module
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

func (c *Runtime) NewPlugin(src []byte, config wazero.ModuleConfig) (Plugin, error) {
	m, err := c.Wazero.InstantiateWithConfig(c.ctx, src, config.WithStartFunctions())
	if err != nil {
		return Plugin{}, err
	}
	return Plugin{Runtime: c, Module: m}, nil
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

func (plugin *Plugin) Call(name string, data []byte) (int32, []byte, error) {
	if err := plugin.SetInput(data); err != nil {
		return -1, []byte{}, err
	}

	f := plugin.Module.ExportedFunction(name)
	if f == nil {
		return -1, []byte{}, errors.New(fmt.Sprintf("Unknown function: %s", name))
	}
	results, err := f.Call(plugin.Runtime.ctx)
	if err != nil {
		return int32(results[0]), []byte{}, err
	}

	if results[0] != 0 {
		errMsg := plugin.GetError()
		return int32(results[0]), []byte{}, errors.New(errMsg)
	}

	output, err := plugin.GetOutput()
	if err != nil {
		return int32(results[0]), []byte{}, err
	}

	return int32(results[0]), output, nil
}

type result struct {
	rc  int32
	err error
}

func (plugin *Plugin) CallWithTimeout(name string, data []byte, timeout time.Duration) (int32, []byte, error) {
	ctx, cancel := context.WithTimeout(plugin.Runtime.ctx, timeout)
	defer cancel()

	if err := plugin.SetInput(data); err != nil {
		return -1, []byte{}, err
	}

	f := plugin.Module.ExportedFunction(name)
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
