package extism

import (
	"context"
	"errors"
	"fmt"
	observe "github.com/dylibso/observe-sdk/go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"os"
	"time"
)

type Plugin struct {
	runtime        wazero.Runtime
	extism         api.Module
	env            wazero.CompiledModule
	main           wazero.CompiledModule
	hasWasi        bool
	manifest       Manifest
	observeAdapter *observe.AdapterBase

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

func NewPlugin(
	ctx context.Context,
	manifest Manifest,
	config PluginConfig,
) (*Plugin, error) {
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

	p := Plugin{
		runtime:        wazero.NewRuntimeWithConfig(ctx, cfg),
		observeAdapter: config.ObserveAdapter,
		manifest:       manifest,
	}

	var err error
	p.extism, err = p.runtime.InstantiateWithConfig(ctx, extismRuntimeWasm, wazero.NewModuleConfig().WithName("extism"))
	if err != nil {
		return nil, err
	}

	if config.EnableWasi {
		wasi_snapshot_preview1.MustInstantiate(ctx, p.runtime)
		p.hasWasi = true
	}

	p.env, err = buildEnvModule(ctx, p.runtime, p.extism)
	if err != nil {
		return nil, err
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

	// Try to find the main module:
	//  - There is always one main module
	//  - If a Wasm value has the Name field set to "main" then use that module
	//  - If there is only one module in the manifest then that is the main module by default
	//  - Otherwise the last module listed is the main module

	var trace *observe.TraceCtx
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

		if data.Name == "main" && config.ObserveAdapter != nil {
			trace, err = config.ObserveAdapter.NewTraceCtx(ctx, p.runtime, data.Data, config.ObserveOptions)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize Observe Adapter: %v", err)
			}

			trace.Finish()
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

		m, err := p.runtime.CompileModule(ctx, data.Data)
		if err != nil {
			return nil, err
		}
		modules[data.Name] = m

		if data.Name == "main" {
			p.main, err = p.runtime.CompileModule(ctx, data.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to compile main module: %v", err)
			}
		}
	}

	if p.main == nil {
		return nil, errors.New("no main module found")
	}

	return &p, nil
}

func (p *Plugin) Instance(ctx context.Context, config PluginInstanceConfig) (*PluginInstance, error) {
	var closers []func(ctx context.Context) error

	// Instantiate the env module which was already pre-compiled as anonymous modules
	// allowing them to be dynamically imported by the import resolver. We'll clean up
	// the env module when the plugin instance is closed.
	env, err := p.runtime.InstantiateModule(ctx, p.env, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("instantiating env module: %w", err)
	}
	closers = append(closers, env.Close)
	ctx = experimental.WithImportResolver(ctx, func(lookupName string) api.Module {
		if lookupName == "extism:host/env" {
			return env
		}
		return nil
	})

	moduleConfig := config.ModuleConfig
	if moduleConfig == nil {
		moduleConfig = wazero.NewModuleConfig()
	}

	// NOTE: this is only necessary for guest modules because
	// host modules have the same access privileges as the host itself
	fs := wazero.NewFSConfig()

	// NOTE: we don't want wazero to call the start function, we will initialize
	// the guest runtime manually.
	// See: https://github.com/extism/go-sdk/pull/1#issuecomment-1650527495
	moduleConfig = moduleConfig.WithStartFunctions().WithFSConfig(fs)

	_, wasiOutput := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT")
	if p.hasWasi && wasiOutput {
		moduleConfig = moduleConfig.WithStderr(os.Stderr).WithStdout(os.Stdout)
	}

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

	instance := &PluginInstance{
		close:                closers,
		plugin:               p,
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
	}
	instance.guestRuntime = detectGuestRuntime(ctx, instance)
	return instance, nil
}
