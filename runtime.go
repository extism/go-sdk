package extism

import (
	"github.com/tetratelabs/wazero/api"
)

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
	initFunc := m.ExportedFunction("hs_init")
	if initFunc == nil {
		return GuestRuntime{}, false
	}

	params := initFunc.Definition().ParamTypes()

	if len(params) != 2 || params[0] != api.ValueTypeI32 || params[1] != api.ValueTypeI32 {
		p.Logf(Trace, "hs_init function found with type %v", params)
	}

	cleanupFunc := m.ExportedFunction("hs_exit")
	if cleanupFunc == nil {
		return GuestRuntime{}, false
	}

	init := func() error {
		_, err := initFunc.Call(p.Runtime.ctx, 0, 0)
		if err == nil {
			p.Log(Debug, "Initialized Haskell language runtime")
		}

		return err
	}

	cleanup := func() error {
		_, err := cleanupFunc.Call(p.Runtime.ctx)
		if err == nil {
			p.Log(Debug, "Cleaned up Haskell language runtime")
		}

		return err
	}

	return GuestRuntime{Type: Haskell, Initialize: init, Cleanup: cleanup}, true
}

// Check for `__wasm__call_ctors` and `__wasm_call_dtors`, this is used by WASI to
// initialize certain interfaces.
func wasiRuntime(p *Plugin, m api.Module) (GuestRuntime, bool) {
	if !p.Runtime.hasWasi {
		return GuestRuntime{}, false
	}

	initFunc := m.ExportedFunction("__wasm_call_ctors")
	if initFunc == nil {
		return GuestRuntime{}, false
	}

	params := initFunc.Definition().ParamTypes()
	if len(params) > 0 {
		p.Logf(Trace, "__wasm_call_ctors function found with type %v", params)
		return GuestRuntime{}, false
	}

	init := func() error {
		_, err := initFunc.Call(p.Runtime.ctx, 0, 0)
		return err
	}

	p.Logf(Trace, "WASI runtime detected")
	cleanupFunc := m.ExportedFunction("__wasm_call_dtors")
	if cleanupFunc != nil {
		params := cleanupFunc.Definition().ParamTypes()
		if len(params) > 0 {
			p.Logf(Trace, "__wasm_call_dtors function found with type %v", params)
			return GuestRuntime{}, false
		}

		cleanup := func() error {
			p.Log(Debug, "Calling __wasm_call_dtors")
			_, err := cleanupFunc.Call(p.Runtime.ctx)
			return err
		}

		return GuestRuntime{Type: Wasi, Initialize: init, Cleanup: cleanup}, true
	}

	return GuestRuntime{Type: Wasi, Initialize: init, Cleanup: nil}, true
}
