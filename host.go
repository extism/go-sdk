package extism

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	// TODO: is there a better package for this?
	"github.com/gobwas/glob"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type ValType = api.ValueType

const I32 = api.ValueTypeI32
const I64 = api.ValueTypeI64

// HostFunctionCallback is a Function implemented in Go instead of a wasm binary.
// The plugin parameter is the calling plugin, used to access memory or
// exported functions and logging.
//
// The stack is includes any parameters encoded according to their ValueType.
// Its length is the max of parameter or result length. When there are results,
// write them in order beginning at index zero. Do not use the stack after the
// function returns.
//
// Here's a typical way to read three parameters and write back one.
//
//	// read parameters in index order
//	argv, argvBuf := api.DecodeU32(inputs[0]), api.DecodeU32(inputs[1])
//
//	// write results back to the stack in index order
//	stack[0] = api.EncodeU32(ErrnoSuccess)
//
// This function can be non-deterministic or cause side effects. It also
// has special properties not defined in the WebAssembly Core specification.
// Notably, this uses the caller's memory (via Module.Memory). See
// https://www.w3.org/TR/wasm-core-1/#host-functions%E2%91%A0
//
// To safely decode/encode values from/to the uint64 inputs/ouputs, users are encouraged to use
// Wazero's api.EncodeXXX or api.DecodeXXX functions.
type HostFunctionCallback func(ctx context.Context, p *CurrentPlugin, userData interface{}, stack []uint64)

// HostFunction represents a custom function defined by the host.
// Here's an example multiplication function that loads operands from memory:
//
//	mult := HostFunction{
//		Name:      "mult",
//		Namespace: "env",
//		Callback: func(ctx context.Context, plugin *CurrentPlugin, userData interface{}, stack []uint64) {
//			a := api.DecodeI32(stack[0])
//			b := api.DecodeI32(stack[1])
//
//			stack[0] = api.EncodeI32(a * b)
//		},
//		Params:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
//		Results: []api.ValueType{api.ValueTypeI64},
//	}
type HostFunction struct {
	Callback  HostFunctionCallback
	Name      string
	Namespace string
	Params    []api.ValueType
	Results   []api.ValueType
	UserData  interface{}
}

type CurrentPlugin struct {
	plugin *Plugin
}

func (p *Plugin) currentPlugin() *CurrentPlugin {
	return &CurrentPlugin{p}
}

func (p *CurrentPlugin) Log(level LogLevel, message string) {
	p.plugin.Log(level, message)
}

func (p *CurrentPlugin) Logf(level LogLevel, format string, args ...any) {
	p.plugin.Logf(level, format, args...)
}

// Memory returns the plugin's WebAssembly memory interface.
func (p *CurrentPlugin) Memory() api.Memory {
	return p.plugin.Memory()
}

// Alloc a new memory block of the given length, returning its offset
func (p *CurrentPlugin) Alloc(n uint64) (uint64, error) {
	out, err := p.plugin.Runtime.Extism.ExportedFunction("extism_alloc").Call(p.plugin.Runtime.ctx, uint64(n))
	if err != nil {
		return 0, err
	} else if len(out) != 1 {
		return 0, fmt.Errorf("Expected 1 return, go %v.", len(out))
	}

	return uint64(out[0]), nil
}

// Free the memory block specified by the given offset
func (p *CurrentPlugin) Free(offset uint64) error {
	_, err := p.plugin.Runtime.Extism.ExportedFunction("extism_free").Call(p.plugin.Runtime.ctx, uint64(offset))
	if err != nil {
		return err
	}

	return nil
}

// Length returns the number of bytes allocated at the specified offset
func (p *CurrentPlugin) Length(offs uint64) (uint64, error) {
	out, err := p.plugin.Runtime.Extism.ExportedFunction("extism_length").Call(p.plugin.Runtime.ctx, uint64(offs))
	if err != nil {
		return 0, err
	} else if len(out) != 1 {
		return 0, fmt.Errorf("Expected 1 return, go %v.", len(out))
	}

	return uint64(out[0]), nil
}

// Write a string to wasm memory and return the offset
func (p *CurrentPlugin) WriteString(s string) (uint64, error) {
	return p.WriteBytes([]byte(s))
}

// WriteBytes writes a string to wasm memory and return the offset
func (p *CurrentPlugin) WriteBytes(b []byte) (uint64, error) {
	ptr, err := p.Alloc(uint64(len(b)))
	if err != nil {
		return 0, err
	}

	ok := p.Memory().Write(uint32(ptr), b)
	if !ok {
		return 0, fmt.Errorf("Failed to write to memory.")
	}

	return ptr, nil
}

// ReadString reads a string from wasm memory
func (p *CurrentPlugin) ReadString(offset uint64) (string, error) {
	buffer, err := p.ReadBytes(offset)
	if err != nil {
		return "", err
	}

	return string(buffer), nil
}

// ReadBytes reads a byte array from memory
func (p *CurrentPlugin) ReadBytes(offset uint64) ([]byte, error) {
	length, err := p.Length(offset)
	if err != nil {
		return []byte{}, err
	}

	buffer, ok := p.Memory().Read(uint32(offset), uint32(length))
	if !ok {
		return []byte{}, fmt.Errorf("Invalid memory block")
	}

	return buffer, nil
}

func buildHostModule(ctx context.Context, rt wazero.Runtime, name string, funcs []HostFunction) (api.Module, error) {
	builder := rt.NewHostModuleBuilder(name)

	defineCustomHostFunctions(builder, funcs)

	return builder.Instantiate(ctx)
}

func defineCustomHostFunctions(builder wazero.HostModuleBuilder, funcs []HostFunction) {
	for _, f := range funcs {

		// Go closures capture variables by reference, not by value.
		// This means that if you directly use f inside the closure without creating
		// a separate variable (closure) and assigning the value of f to it, you might run into unexpected behavior.
		// All the closures created in the loop would end up referencing the same f, which could lead to incorrect or unintended results.
		// See: https://github.com/extism/go-sdk/issues/5#issuecomment-1666774486
		closure := f

		builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
			if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
				closure.Callback(ctx, &CurrentPlugin{plugin}, closure.UserData, stack)
				return
			}

			panic("Invalid context, `plugin` key not found")
		}), closure.Params, closure.Results).Export(closure.Name)
	}
}

func buildEnvModule(ctx context.Context, rt wazero.Runtime, extism api.Module, funcs []HostFunction) (api.Module, error) {
	builder := rt.NewHostModuleBuilder("env")

	wrap := func(name string, params []ValType, results []ValType) {
		builder.
			NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				f := extism.ExportedFunction(name)
				err := f.CallWithStack(ctx, stack)
				if err != nil {
					panic(err)
				}
			}), params, results).
			Export(name)
	}

	wrap("extism_alloc", []ValType{I64}, []ValType{I64})
	wrap("extism_free", []ValType{I64}, []ValType{})
	wrap("extism_load_u64", []ValType{I64}, []ValType{I64})
	wrap("extism_load_u8", []ValType{I64}, []ValType{I32})
	wrap("extism_input_load_u64", []ValType{I64}, []ValType{I64})
	wrap("extism_input_load_u8", []ValType{I64}, []ValType{I32})
	wrap("extism_store_u64", []ValType{I64, I64}, []ValType{})
	wrap("extism_store_u8", []ValType{I64, I32}, []ValType{})
	wrap("extism_input_set", []ValType{I64, I64}, []ValType{})
	wrap("extism_output_set", []ValType{I64, I64}, []ValType{})
	wrap("extism_input_length", []ValType{}, []ValType{I64})
	wrap("extism_input_offset", []ValType{}, []ValType{I64})
	wrap("extism_output_length", []ValType{}, []ValType{I64})
	wrap("extism_output_offset", []ValType{}, []ValType{I64})
	wrap("extism_length", []ValType{I64}, []ValType{I64})
	wrap("extism_reset", []ValType{}, []ValType{})
	wrap("extism_error_set", []ValType{I64}, []ValType{})
	wrap("extism_error_get", []ValType{}, []ValType{I64})
	wrap("extism_memory_bytes", []ValType{}, []ValType{I64})

	hostFunc := func(name string, f interface{}) {
		builder.NewFunctionBuilder().WithFunc(f).Export(name)
	}

	hostFunc("extism_config_get", configGet)
	hostFunc("extism_var_get", varGet)
	hostFunc("extism_var_set", varSet)
	hostFunc("extism_http_request", httpRequest)
	hostFunc("extism_http_status_code", httpStatusCode)

	defineCustomHostFunctions(builder, funcs)

	logFunc := func(name string, level LogLevel) {
		hostFunc(name, func(ctx context.Context, m api.Module, offset uint64) {
			if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
				message, err := plugin.currentPlugin().ReadString(offset)
				if err != nil {
					panic(fmt.Errorf("Failed to read log message from memory: %v", err))
				}

				plugin.Log(level, message)

				return
			}

			panic("Invalid context, `plugin` key not found")
		})
	}

	logFunc("extism_log_debug", Debug)
	logFunc("extism_log_info", Info)
	logFunc("extism_log_warn", Warn)
	logFunc("extism_log_error", Error)

	return builder.Instantiate(ctx)
}

func configGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		cp := plugin.currentPlugin()

		name, err := cp.ReadString(offset)
		if err != nil {
			panic(fmt.Errorf("Failed to read config name from memory: %v", err))
		}

		value, ok := plugin.Config[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		offset, err = cp.WriteString(value)
		if err != nil {
			panic(fmt.Errorf("Failed to write config value to memory: %v", err))
		}

		return offset
	}

	panic("Invalid context, `plugin` key not found")
}

func varGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		cp := plugin.currentPlugin()

		name, err := cp.ReadString(offset)
		if err != nil {
			panic(fmt.Errorf("Failed to read var name from memory: %v", err))
		}

		value, ok := plugin.Var[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		offset, err = cp.WriteBytes(value)
		if err != nil {
			panic(fmt.Errorf("Failed to write var value to memory: %v", err))
		}

		return offset
	}

	panic("Invalid context, `plugin` key not found")
}

func varSet(ctx context.Context, m api.Module, nameOffset uint64, valueOffset uint64) {
	plugin, ok := ctx.Value("plugin").(*Plugin)
	if !ok {
		panic("Invalid context, `plugin` key not found")
	}

	cp := plugin.currentPlugin()

	name, err := cp.ReadString(nameOffset)
	if err != nil {
		panic(fmt.Errorf("Failed to read var name from memory: %v", err))
	}

	size := 0
	for _, v := range plugin.Var {
		size += len(v)
	}

	// If the store is larger than 100MB then stop adding things
	if size > 1024*1024*100 && valueOffset != 0 {
		panic("Variable store is full")
	}

	// Remove if the value offset is 0
	if valueOffset == 0 {
		delete(plugin.Var, name)
	} else {
		value, err := cp.ReadBytes(valueOffset)
		if err != nil {
			panic(fmt.Errorf("Failed to read var value from memory: %v", err))
		}

		plugin.Var[name] = value
	}
}

func httpRequest(ctx context.Context, m api.Module, requestOffset uint64, bodyOffset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		cp := plugin.currentPlugin()

		requestJson, err := cp.ReadBytes(requestOffset)
		var request HttpRequest
		err = json.Unmarshal(requestJson, &request)
		if err != nil {
			panic(fmt.Errorf("Invalid HTTP Request: %v", err))
		}

		url, err := url.Parse(request.Url)
		if err != nil {
			panic(fmt.Errorf("Invalid Url: %v", err))
		}

		// deny all requests by default
		hostMatches := false
		for _, allowedHost := range plugin.AllowedHosts {
			if allowedHost == url.Hostname() {
				hostMatches = true
				break
			}

			pattern := glob.MustCompile(allowedHost)
			if pattern.Match(url.Hostname()) {
				hostMatches = true
				break
			}
		}

		if !hostMatches {
			panic(fmt.Errorf("HTTP request to '%v' is not allowed", request.Url))
		}

		var bodyReader io.Reader = nil
		if bodyOffset != 0 {
			body, err := cp.ReadBytes(bodyOffset)
			if err != nil {
				panic("Failed to read response body from memory")
			}

			cp.Free(bodyOffset)

			bodyReader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, request.Method, request.Url, bodyReader)
		if err != nil {
			panic(err)
		}

		for key, value := range request.Headers {
			req.Header.Set(key, value)
		}

		client := http.DefaultClient
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		plugin.LastStatusCode = resp.StatusCode

		// TODO: make this limit configurable
		// TODO: the rust implementation silently truncates the response body, should we keep the behavior here?
		limiter := http.MaxBytesReader(nil, resp.Body, 1024*1024*50)
		body, err := ioutil.ReadAll(limiter)
		if err != nil {
			panic(err)
		}

		if len(body) == 0 {
			return 0
		} else {
			offset, err := cp.WriteBytes(body)
			if err != nil {
				panic("Failed to write resposne body to memory")
			}

			return offset
		}
	}

	panic("Invalid context, `plugin` key not found")
}

func httpStatusCode(ctx context.Context, m api.Module) int32 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		return int32(plugin.LastStatusCode)
	}

	panic("Invalid context, `plugin` key not found")
}
