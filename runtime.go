package extism

import (
	"github.com/tetratelabs/wazero/api"
)

// TODO: test runtime initialization/cleanup for WASI and Haskell

type RuntimeType uint8

const (
	None RuntimeType = iota
	Haskell
	Wasi
)

type GuestRuntime struct {
	Type       RuntimeType
	Initialize func() error
	Cleanup    func() error
}

func guestRuntime(p *Plugin, m api.Module) GuestRuntime {
	runtime, ok := haskellRuntime(p, m)
	if ok {
		return runtime
	}

	runtime, ok = wasiRuntime(p, m)
	if ok {
		return runtime
	}

	p.Log(Trace, "No runtime detected")
	return GuestRuntime{Type: None, Initialize: func() error { return nil }}
}

// Check for Haskell runtime initialization functions
// Initialize Haskell runtime if `hs_init` and `hs_exit` are present,
// by calling the `hs_init` export
func haskellRuntime(p *Plugin, m api.Module) (GuestRuntime, bool) {
	init := findFunc(m, p, "hs_init", api.ValueTypeI32, api.ValueTypeI32)
	if init == nil {
		return GuestRuntime{}, false
	}

	cleanup := findFunc(m, p, "hs_exit")
	if cleanup == nil {
		return GuestRuntime{}, false
	}

	return GuestRuntime{Type: Haskell, Initialize: init, Cleanup: cleanup}, true
}

// Check for initialization and cleanup functions defined by the WASI standard
func wasiRuntime(p *Plugin, m api.Module) (GuestRuntime, bool) {
	if !p.Runtime.hasWasi {
		return GuestRuntime{}, false
	}

	// WASI supports two modules: Reactors and Commands
	// we prioritize Reactors over Commands
	// see: https://github.com/WebAssembly/WASI/blob/main/legacy/application-abi.md
	if r, ok := reactorModule(m, p); ok {
		return r, ok
	}

	return commandModule(m, p)
}

// Check for `_initialize` this is used by WASI to initialize certain interfaces.
func reactorModule(m api.Module, p *Plugin) (GuestRuntime, bool) {
	init := findFunc(m, p, "_initialize")
	if init == nil {
		return GuestRuntime{}, false
	}

	p.Logf(Trace, "WASI runtime detected")
	p.Logf(Trace, "Reactor module detected")

	return GuestRuntime{Type: Wasi, Initialize: init, Cleanup: nil}, true
}

// Check for `__wasm__call_ctors` and `__wasm_call_dtors`, this is used by WASI to
// initialize certain interfaces.
func commandModule(m api.Module, p *Plugin) (GuestRuntime, bool) {
	init := findFunc(m, p, "__wasm_call_ctors")
	if init == nil {
		return GuestRuntime{}, false
	}

	p.Logf(Trace, "WASI runtime detected")
	p.Logf(Trace, "Command module detected")
	cleanup := findFunc(m, p, "__wasm_call_dtors")

	return GuestRuntime{Type: Wasi, Initialize: init, Cleanup: cleanup}, true
}

func findFunc(m api.Module, p *Plugin, name string, expectedParams ...byte) func() error {
	initFunc := m.ExportedFunction(name)
	if initFunc == nil {
		return nil
	}

	params := initFunc.Definition().ParamTypes()
	if !equal(params, expectedParams) {
		p.Logf(Trace, "%v function found with type %v", name, params)
		return nil
	}

	return func() error {
		p.Logf(Debug, "Calling %v", name)
		_, err := initFunc.Call(p.Runtime.ctx, 0, 0)
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
