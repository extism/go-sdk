package extism

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// TODO: test runtime initialization for WASI and Haskell

type runtimeType uint8

const (
	None runtimeType = iota
	Haskell
	Wasi
)

type guestRuntime struct {
	runtimeType runtimeType
	init        func(ctx context.Context) error
	initialized bool
}

func detectGuestRuntime(ctx context.Context, p *Plugin) guestRuntime {
	m := p.Main

	runtime, ok := haskellRuntime(ctx, p, m)
	if ok {
		return runtime
	}

	runtime, ok = wasiRuntime(ctx, p, m)
	if ok {
		return runtime
	}

	p.Log(LogLevelTrace, "No runtime detected")
	return guestRuntime{runtimeType: None, init: func(_ context.Context) error { return nil }, initialized: true}
}

// Check for Haskell runtime initialization functions
// Initialize Haskell runtime if `hs_init` and `hs_exit` are present,
// by calling the `hs_init` export
func haskellRuntime(ctx context.Context, p *Plugin, m api.Module) (guestRuntime, bool) {
	initFunc := m.ExportedFunction("hs_init")
	if initFunc == nil {
		return guestRuntime{}, false
	}

	params := initFunc.Definition().ParamTypes()

	if len(params) != 2 || params[0] != api.ValueTypeI32 || params[1] != api.ValueTypeI32 {
		p.Logf(LogLevelTrace, "hs_init function found with type %v", params)
	}

	reactorInit := m.ExportedFunction("_initialize")

	init := func(ctx context.Context) error {
		if reactorInit != nil {
			_, err := reactorInit.Call(ctx)
			if err != nil {
				p.Logf(LogLevelError, "Error running reactor _initialize: %s", err.Error())
			}
		}
		_, err := initFunc.Call(ctx, 0, 0)
		if err == nil {
			p.Log(LogLevelDebug, "Initialized Haskell language runtime.")
		}

		return err
	}

	p.Log(LogLevelTrace, "Haskell runtime detected")
	return guestRuntime{runtimeType: Haskell, init: init}, true
}

// Check for initialization functions defined by the WASI standard
func wasiRuntime(ctx context.Context, p *Plugin, m api.Module) (guestRuntime, bool) {
	if !p.Runtime.hasWasi {
		return guestRuntime{}, false
	}

	// WASI supports two modules: Reactors and Commands
	// we prioritize Reactors over Commands
	// see: https://github.com/WebAssembly/WASI/blob/main/legacy/application-abi.md
	if r, ok := reactorModule(ctx, m, p); ok {
		return r, ok
	}

	return commandModule(ctx, m, p)
}

// Check for `_initialize` this is used by WASI to initialize certain interfaces.
func reactorModule(ctx context.Context, m api.Module, p *Plugin) (guestRuntime, bool) {
	init := findFunc(ctx, m, p, "_initialize")
	if init == nil {
		return guestRuntime{}, false
	}

	p.Logf(LogLevelTrace, "WASI runtime detected")
	p.Logf(LogLevelTrace, "Reactor module detected")

	return guestRuntime{runtimeType: Wasi, init: init}, true
}

// Check for `__wasm__call_ctors`, this is used by WASI to
// initialize certain interfaces.
func commandModule(ctx context.Context, m api.Module, p *Plugin) (guestRuntime, bool) {
	init := findFunc(ctx, m, p, "__wasm_call_ctors")
	if init == nil {
		return guestRuntime{}, false
	}

	p.Logf(LogLevelTrace, "WASI runtime detected")
	p.Logf(LogLevelTrace, "Command module detected")

	return guestRuntime{runtimeType: Wasi, init: init}, true
}

func findFunc(ctx context.Context, m api.Module, p *Plugin, name string) func(context.Context) error {
	initFunc := m.ExportedFunction(name)
	if initFunc == nil {
		return nil
	}

	params := initFunc.Definition().ParamTypes()
	if len(params) != 0 {
		p.Logf(LogLevelTrace, "%v function found with type %v", name, params)
		return nil
	}

	return func(ctx context.Context) error {
		p.Logf(LogLevelDebug, "Calling %v", name)
		_, err := initFunc.Call(ctx)
		return err
	}
}

func equal(actual []byte, expected []byte) bool {
	if len(actual) != len(expected) {
		return false
	}

	for i, k := range actual {
		if expected[i] != k {
			return false
		}
	}

	return true
}
