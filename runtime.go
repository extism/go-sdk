package extism

import (
	"github.com/tetratelabs/wazero/api"
)

// TODO: test runtime initialization for WASI and Haskell

type RuntimeType uint8

const (
	None RuntimeType = iota
	Haskell
	Wasi
)

type GuestRuntime struct {
	Type        RuntimeType
	Init        func() error
	initialized bool
}

func guestRuntime(p *Plugin) GuestRuntime {
	m := p.Main

	runtime, ok := haskellRuntime(p, m)
	if ok {
		return runtime
	}

	runtime, ok = wasiRuntime(p, m)
	if ok {
		return runtime
	}

	p.Log(Trace, "No runtime detected")
	return GuestRuntime{Type: None, Init: func() error { return nil }, initialized: true}
}

// Check for Haskell runtime initialization functions
// Initialize Haskell runtime if `hs_init` and `hs_exit` are present,
// by calling the `hs_init` export
func haskellRuntime(p *Plugin, m api.Module) (GuestRuntime, bool) {
	initFunc := m.ExportedFunction("hs_init")
	if initFunc == nil {
		return GuestRuntime{}, false
	}

	params := initFunc.Definition().ParamTypes()

	if len(params) != 2 || params[0] != api.ValueTypeI32 || params[1] != api.ValueTypeI32 {
		p.Logf(Trace, "hs_init function found with type %v", params)
	}

	reactorInit := m.ExportedFunction("_initialize")

	init := func() error {
		if reactorInit != nil {
			_, err := reactorInit.Call(p.Runtime.ctx)
			if err != nil {
				p.Logf(Error, "Error running reactor _initialize: %s", err.Error())
			}
		}
		_, err := initFunc.Call(p.Runtime.ctx, 0, 0)
		if err == nil {
			p.Log(Debug, "Initialized Haskell language runtime.")
		}

		return err
	}

	p.Log(Trace, "Haskell runtime detected")
	return GuestRuntime{Type: Haskell, Init: init}, true
}

// Check for initialization functions defined by the WASI standard
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

	return GuestRuntime{Type: Wasi, Init: init}, true
}

// Check for `__wasm__call_ctors`, this is used by WASI to
// initialize certain interfaces.
func commandModule(m api.Module, p *Plugin) (GuestRuntime, bool) {
	init := findFunc(m, p, "__wasm_call_ctors")
	if init == nil {
		return GuestRuntime{}, false
	}

	p.Logf(Trace, "WASI runtime detected")
	p.Logf(Trace, "Command module detected")

	return GuestRuntime{Type: Wasi, Init: init}, true
}

func findFunc(m api.Module, p *Plugin, name string) func() error {
	initFunc := m.ExportedFunction(name)
	if initFunc == nil {
		return nil
	}

	params := initFunc.Definition().ParamTypes()
	if len(params) != 0 {
		p.Logf(Trace, "%v function found with type %v", name, params)
		return nil
	}

	return func() error {
		p.Logf(Debug, "Calling %v", name)
		_, err := initFunc.Call(p.Runtime.ctx)
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
