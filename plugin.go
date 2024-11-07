package extism

import (
	"context"
	"errors"
	"fmt"
	observe "github.com/dylibso/observe-sdk/go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type CompiledPlugin struct {
	runtime wazero.Runtime
	main    wazero.CompiledModule
	extism  wazero.CompiledModule
	env     api.Module

	// when a module (main) is instantiated, it may have a module name that's added
	// to the data section of the wasm. If this is the case, we won't be able to
	// instantiate that module more than once. This counter acts as the module name
	// incrementing each time we instantiate the module.
	instanceCount atomic.Uint64

	// this is the raw wasm bytes of the provided module, it is required when using a tracing observeAdapter.
	// If an adapter is not provided, this field will be nil.
	wasmBytes      []byte
	hasWasi        bool
	manifest       Manifest
	observeAdapter *observe.AdapterBase
	observeOptions *observe.Options

	maxHttp int64
	maxVar  int64
}

type PluginConfig struct {
	RuntimeConfig  wazero.RuntimeConfig
	EnableWasi     bool
	ObserveAdapter *observe.AdapterBase
	ObserveOptions *observe.Options
	HostFunctions  []HostFunction
}

func NewCompiledPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
) (*CompiledPlugin, error) {
	count := len(manifest.Wasm)
	if count == 0 {
		return nil, fmt.Errorf("manifest can't be empty")
	}

	var cfg wazero.RuntimeConfig
	if config.RuntimeConfig == nil {
		cfg = wazero.NewRuntimeConfig()
	} else {
		cfg = config.RuntimeConfig
	}

	// Make sure function calls are cancelled if the context is cancelled
	if manifest.Timeout > 0 {
		cfg = cfg.WithCloseOnContextDone(true)
	}

	if manifest.Memory != nil {
		if manifest.Memory.MaxPages > 0 {
			cfg = cfg.WithMemoryLimitPages(manifest.Memory.MaxPages)
		}
	}

	p := CompiledPlugin{
		manifest:       manifest,
		runtime:        wazero.NewRuntimeWithConfig(ctx, cfg),
		observeAdapter: config.ObserveAdapter,
		observeOptions: config.ObserveOptions,
	}

	if config.EnableWasi {
		wasi_snapshot_preview1.MustInstantiate(ctx, p.runtime)
		p.hasWasi = true
	}

	// Build host modules
	hostModules := make(map[string][]HostFunction)
	for _, f := range config.HostFunctions {
		hostModules[f.Namespace] = append(hostModules[f.Namespace], f)
	}
	for name, funcs := range hostModules {
		_, err := buildHostModule(ctx, p.runtime, name, funcs)
		if err != nil {
			return nil, fmt.Errorf("building host module: %w", err)
		}
	}

	// Compile the extism module
	var err error
	p.extism, err = p.runtime.CompileModule(ctx, extismRuntimeWasm)
	if err != nil {
		return nil, fmt.Errorf("instantiating extism module: %w", err)
	}

	// Build and instantiate extism:host/env module
	p.env, err = instantiateEnvModule(ctx, p.runtime)
	if err != nil {
		return nil, err
	}

	// Try to find the main module:
	//  - There is always one main module
	//  - If a Wasm value has the Name field set to "main" then use that module
	//  - If there is only one module in the manifest then that is the main module by default
	//  - Otherwise the last module listed is the main module

	modules := map[string]wazero.CompiledModule{}
	for i, wasm := range manifest.Wasm {
		data, err := wasm.ToWasmData(ctx)
		if err != nil {
			return nil, err
		}

		_, mainExists := modules["main"]
		if data.Name == "" || i == len(manifest.Wasm)-1 && !mainExists {
			data.Name = "main"
		}

		_, okm := modules[data.Name]

		if data.Name == "extism:host/env" || okm {
			return nil, fmt.Errorf("module name collision: '%s'", data.Name)
		}

		if data.Hash != "" {
			calculatedHash := calculateHash(data.Data)
			if data.Hash != calculatedHash {
				return nil, fmt.Errorf("hash mismatch for module '%s'", data.Name)
			}
		}

		if p.observeAdapter != nil {
			p.wasmBytes = data.Data
		}

		m, err := p.runtime.CompileModule(ctx, data.Data)
		if err != nil {
			return nil, err
		}
		if data.Name == "main" {
			p.main = m
		} else {
			modules[data.Name] = m
		}
	}

	if p.main == nil {
		return nil, errors.New("no main module found")
	}

	// We no longer need the wasm in the manifest so nil it
	// to make the slice eligible for garbage collection.
	p.manifest.Wasm = nil

	return &p, nil
}

func (p *CompiledPlugin) Close(ctx context.Context) error {
	return p.runtime.Close(ctx)
}

func (p *CompiledPlugin) Instance(ctx context.Context, config PluginInstanceConfig) (*Plugin, error) {
	var closers []func(ctx context.Context) error

	moduleConfig := config.ModuleConfig
	if moduleConfig == nil {
		moduleConfig = wazero.NewModuleConfig()
	}
	moduleConfig = moduleConfig.WithName(strconv.Itoa(int(p.instanceCount.Add(1))))

	// NOTE: this is only necessary for guest modules because
	// host modules have the same access privileges as the host itself
	fs := wazero.NewFSConfig()
	for host, guest := range p.manifest.AllowedPaths {
		if strings.HasPrefix(host, "ro:") {
			trimmed := strings.TrimPrefix(host, "ro:")
			fs = fs.WithReadOnlyDirMount(trimmed, guest)
		} else {
			fs = fs.WithDirMount(host, guest)
		}
	}

	// NOTE: we don't want wazero to call the start function, we will initialize
	// the guest runtime manually.
	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
	moduleConfig = moduleConfig.WithStartFunctions().WithFSConfig(fs)

	_, wasiOutput := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT")
	if p.hasWasi && wasiOutput {
		moduleConfig = moduleConfig.WithStderr(os.Stderr).WithStdout(os.Stdout)
	}

	var trace *observe.TraceCtx
	var err error
	if p.observeAdapter != nil {
		trace, err = p.observeAdapter.NewTraceCtx(ctx, p.runtime, p.wasmBytes, p.observeOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Observe Adapter: %v", err)
		}

		trace.Finish()
	}

	// Compile and instantiate the extism runtime. This runtime is stateful and needs to be
	// instantiated on a per-instance basis. We don't provide a name because the module needs
	// to be anonymous -- you cannot instantiate multiple modules with the same name into the
	// same runtime. It is okay that this is anonymous, because this module is only called
	// from Go host functions and not from the Wasm module itself.
	extism, err := p.runtime.InstantiateModule(ctx, p.extism, wazero.NewModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("instantiating extism module: %w", err)
	}
	closers = append(closers, extism.Close)

	main, err := p.runtime.InstantiateModule(ctx, p.main, moduleConfig)
	if err != nil {
		return nil, fmt.Errorf("instantiating module: %w", err)
	}
	closers = append(closers, main.Close)

	p.maxHttp = int64(1024 * 1024 * 50)
	if p.manifest.Memory != nil && p.manifest.Memory.MaxHttpResponseBytes >= 0 {
		p.maxHttp = p.manifest.Memory.MaxHttpResponseBytes
	}

	p.maxVar = int64(1024 * 1024)
	if p.manifest.Memory != nil && p.manifest.Memory.MaxVarBytes >= 0 {
		p.maxVar = p.manifest.Memory.MaxVarBytes
	}

	instance := &Plugin{
		close:                closers,
		extism:               extism,
		hasWasi:              p.hasWasi,
		module:               main,
		Timeout:              time.Duration(p.manifest.Timeout) * time.Millisecond,
		Config:               p.manifest.Config,
		Var:                  make(map[string][]byte),
		AllowedHosts:         p.manifest.AllowedHosts,
		AllowedPaths:         p.manifest.AllowedPaths,
		LastStatusCode:       0,
		MaxHttpResponseBytes: p.maxHttp,
		MaxVarBytes:          p.maxVar,
		guestRuntime:         guestRuntime{},
		Adapter:              p.observeAdapter,
		log:                  logStd,
		traceCtx:             trace,
	}
	instance.guestRuntime = detectGuestRuntime(ctx, instance)
	return instance, nil
}

func NewPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
	functions []HostFunction,
) (*Plugin, error) {
	if config.HostFunctions == nil {
		config.HostFunctions = []HostFunction{}
	}
	config.HostFunctions = append(config.HostFunctions, functions...)
	c, err := NewCompiledPlugin(ctx, manifest, config)
	if err != nil {
		return nil, err
	}
	return c.Instance(ctx, PluginInstanceConfig{})
}
