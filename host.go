package extism

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"unsafe"

	// TODO: is there a better package for this?
	"github.com/gobwas/glob"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type ValueType = byte

const (
	// ValueTypeI32 is a 32-bit integer.
	ValueTypeI32 = api.ValueTypeI32
	// ValueTypeI64 is a 64-bit integer.
	ValueTypeI64 = api.ValueTypeI64
	// ValueTypeF32 is a 32-bit floating point number.
	ValueTypeF32 = api.ValueTypeF32
	// ValueTypeF64 is a 64-bit floating point number.
	ValueTypeF64 = api.ValueTypeF64
	// ValueTypePTR represents a pointer to an Extism memory block. Alias for ValueTypeI64
	ValueTypePTR = ValueTypeI64
)

// HostFunctionStackCallback is a Function implemented in Go instead of a wasm binary.
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
//	argv, argvBuf := DecodeU32(inputs[0]), DecodeU32(inputs[1])
//
//	// write results back to the stack in index order
//	stack[0] = EncodeU32(ErrnoSuccess)
//
// This function can be non-deterministic or cause side effects. It also
// has special properties not defined in the WebAssembly Core specification.
// Notably, this uses the caller's memory (via Module.Memory). See
// https://www.w3.org/TR/wasm-core-1/#host-functions%E2%91%A0
//
// To safely decode/encode values from/to the uint64 inputs/ouputs, users are encouraged to use
// Extism's EncodeXXX or DecodeXXX functions.
type HostFunctionStackCallback func(ctx context.Context, p *CurrentPlugin, stack []uint64)

// HostFunction represents a custom function defined by the host.
type HostFunction struct {
	stackCallback HostFunctionStackCallback
	Name          string
	Namespace     string
	Params        []api.ValueType
	Returns       []api.ValueType
}

func (f *HostFunction) SetNamespace(namespace string) {
	f.Namespace = namespace
}

// NewHostFunctionWithStack creates a new instance of a HostFunction, which is designed
// to provide custom functionality in a given host environment.
// Here's an example multiplication function that loads operands from memory:
//
//	 mult := NewHostFunctionWithStack(
//		"mult",
//		func(ctx context.Context, plugin *CurrentPlugin, stack []uint64) {
//			a := DecodeI32(stack[0])
//			b := DecodeI32(stack[1])
//
//			stack[0] = EncodeI32(a * b)
//		},
//		[]ValueType{ValueTypeI64, ValueTypeI64},
//		ValueTypeI64
//	 )
func NewHostFunctionWithStack(
	name string,
	callback HostFunctionStackCallback,
	params []ValueType,
	returnTypes []ValueType) HostFunction {

	return HostFunction{
		stackCallback: callback,
		Name:          name,
		Namespace:     "extism:host/user",
		Params:        params,
		Returns:       returnTypes,
	}
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
	return p.AllocWithContext(context.Background(), n)
}

// Alloc a new memory block of the given length, returning its offset
func (p *CurrentPlugin) AllocWithContext(ctx context.Context, n uint64) (uint64, error) {
	out, err := p.plugin.Runtime.Extism.ExportedFunction("alloc").Call(ctx, uint64(n))
	if err != nil {
		return 0, err
	} else if len(out) != 1 {
		return 0, fmt.Errorf("Expected 1 return, go %v.", len(out))
	}

	return uint64(out[0]), nil
}

// Free the memory block specified by the given offset
func (p *CurrentPlugin) Free(offset uint64) error {
	return p.FreeWithContext(context.Background(), offset)
}

// Free the memory block specified by the given offset
func (p *CurrentPlugin) FreeWithContext(ctx context.Context, offset uint64) error {
	_, err := p.plugin.Runtime.Extism.ExportedFunction("free").Call(ctx, uint64(offset))
	if err != nil {
		return err
	}

	return nil
}

// Length returns the number of bytes allocated at the specified offset
func (p *CurrentPlugin) Length(offs uint64) (uint64, error) {
	return p.LengthWithContext(context.Background(), offs)
}

// Length returns the number of bytes allocated at the specified offset
func (p *CurrentPlugin) LengthWithContext(ctx context.Context, offs uint64) (uint64, error) {
	out, err := p.plugin.Runtime.Extism.ExportedFunction("length").Call(ctx, uint64(offs))
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

	cpy := make([]byte, len(buffer))
	copy(cpy, buffer)

	return cpy, nil
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
		closure := f.stackCallback

		builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
			if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
				closure(ctx, &CurrentPlugin{plugin}, stack)
				return
			}

			panic("Invalid context, `plugin` key not found")
		}), f.Params, f.Returns).Export(f.Name)
	}
}

func buildEnvModule(ctx context.Context, rt wazero.Runtime, extism api.Module) (api.Module, error) {
	builder := rt.NewHostModuleBuilder("extism:host/env")

	wrap := func(name string, params []ValueType, results []ValueType) {
		f := extism.ExportedFunction(name)
		builder.
			NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				err := f.CallWithStack(ctx, stack)
				if err != nil {
					panic(err)
				}
			}), params, results).
			Export(name)
	}

	wrap("alloc", []ValueType{ValueTypeI64}, []ValueType{ValueTypeI64})
	wrap("free", []ValueType{ValueTypeI64}, []ValueType{})
	wrap("load_u8", []ValueType{ValueTypeI64}, []ValueType{ValueTypeI32})
	wrap("input_load_u8", []ValueType{ValueTypeI64}, []ValueType{ValueTypeI32})
	wrap("store_u64", []ValueType{ValueTypeI64, ValueTypeI64}, []ValueType{})
	wrap("store_u8", []ValueType{ValueTypeI64, ValueTypeI32}, []ValueType{})
	wrap("input_set", []ValueType{ValueTypeI64, ValueTypeI64}, []ValueType{})
	wrap("output_set", []ValueType{ValueTypeI64, ValueTypeI64}, []ValueType{})
	wrap("input_length", []ValueType{}, []ValueType{ValueTypeI64})
	wrap("input_offset", []ValueType{}, []ValueType{ValueTypeI64})
	wrap("output_length", []ValueType{}, []ValueType{ValueTypeI64})
	wrap("output_offset", []ValueType{}, []ValueType{ValueTypeI64})
	wrap("length", []ValueType{ValueTypeI64}, []ValueType{ValueTypeI64})
	wrap("length_unsafe", []ValueType{ValueTypeI64}, []ValueType{ValueTypeI64})
	wrap("reset", []ValueType{}, []ValueType{})
	wrap("error_set", []ValueType{ValueTypeI64}, []ValueType{})
	wrap("error_get", []ValueType{}, []ValueType{ValueTypeI64})
	wrap("memory_bytes", []ValueType{}, []ValueType{ValueTypeI64})

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(api.GoModuleFunc(inputLoad_u64)), []ValueType{ValueTypeI64}, []ValueType{ValueTypeI64}).
		Export("input_load_u64")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(load_u64), []ValueType{ValueTypeI64}, []ValueType{ValueTypeI64}).
		Export("load_u64")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(store_u64), []ValueType{ValueTypeI64, ValueTypeI64}, []ValueType{}).
		Export("store_u64")

	hostFunc := func(name string, f interface{}) {
		builder.NewFunctionBuilder().WithFunc(f).Export(name)
	}

	hostFunc("config_get", configGet)
	hostFunc("var_get", varGet)
	hostFunc("var_set", varSet)
	hostFunc("http_request", httpRequest)
	hostFunc("http_status_code", httpStatusCode)

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

	logFunc("log_debug", LogLevelDebug)
	logFunc("log_info", LogLevelInfo)
	logFunc("log_warn", LogLevelWarn)
	logFunc("log_error", LogLevelError)

	return builder.Instantiate(ctx)
}

func store_u64(ctx context.Context, mod api.Module, stack []uint64) {
	p, ok := ctx.Value("plugin").(*Plugin)
	if !ok {
		panic("Invalid context")
	}

	offset := stack[0]
	value := stack[1]
	ok = p.Memory().WriteUint64Le(uint32(offset), value)
	if !ok {
		panic(fmt.Sprintf("could not write value '%v' at offset: %v", value, offset))
	}
}

func load_u64(ctx context.Context, mod api.Module, stack []uint64) {
	p, ok := ctx.Value("plugin").(*Plugin)
	if !ok {
		panic("Invalid context")
	}

	stack[0], ok = p.Memory().ReadUint64Le(uint32(stack[0]))
	if !ok {
		panic(fmt.Sprintf("could not read value at offset: %v", stack[0]))
	}
}

func inputLoad_u64(ctx context.Context, mod api.Module, stack []uint64) {
	p, ok := ctx.Value("plugin").(*Plugin)
	if !ok {
		panic("Invalid context")
	}

	offset, ok := ctx.Value("inputOffset").(uint64)
	if !ok {
		panic("Invalid context")
	}

	stack[0], ok = p.Memory().ReadUint64Le(uint32(stack[0] + offset))
	if !ok {
		panic(fmt.Sprintf("could not read value at offset: %v", stack[0]))
	}
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

	if plugin.MaxVarBytes == 0 {
		panic("Vars are disabled by this host")
	}

	cp := plugin.currentPlugin()

	name, err := cp.ReadString(nameOffset)
	if err != nil {
		panic(fmt.Errorf("Failed to read var name from memory: %v", err))
	}

	// Remove if the value offset is 0
	if valueOffset == 0 {
		delete(plugin.Var, name)
		return
	}

	value, err := cp.ReadBytes(valueOffset)
	if err != nil {
		panic(fmt.Errorf("Failed to read var value from memory: %v", err))
	}

	// Calculate size including current key/value
	size := int(unsafe.Sizeof([]byte{})+unsafe.Sizeof("")) + len(name) + len(value)
	for k, v := range plugin.Var {
		size += len(k)
		size += len(v)
		size += int(unsafe.Sizeof([]byte{}) + unsafe.Sizeof(""))
	}

	if size >= int(plugin.MaxVarBytes) && valueOffset != 0 {
		panic("Variable store is full")
	}

	plugin.Var[name] = value
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

		limiter := http.MaxBytesReader(nil, resp.Body, int64(plugin.MaxHttpResponseBytes))
		body, err := io.ReadAll(limiter)
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

// EncodeI32 encodes the input as a ValueTypeI32.
func EncodeI32(input int32) uint64 {
	return api.EncodeI32(input)
}

// DecodeI32 decodes the input as a ValueTypeI32.
func DecodeI32(input uint64) int32 {
	return api.DecodeI32(input)
}

// EncodeU32 encodes the input as a ValueTypeI32.
func EncodeU32(input uint32) uint64 {
	return api.EncodeU32(input)
}

// DecodeU32 decodes the input as a ValueTypeI32.
func DecodeU32(input uint64) uint32 {
	return api.DecodeU32(input)
}

// EncodeI64 encodes the input as a ValueTypeI64.
func EncodeI64(input int64) uint64 {
	return api.EncodeI64(input)
}

// EncodeF32 encodes the input as a ValueTypeF32.
//
// See DecodeF32
func EncodeF32(input float32) uint64 {
	return api.EncodeF32(input)
}

// DecodeF32 decodes the input as a ValueTypeF32.
//
// See EncodeF32
func DecodeF32(input uint64) float32 {
	return api.DecodeF32(input)
}

// EncodeF64 encodes the input as a ValueTypeF64.
//
// See EncodeF32
func EncodeF64(input float64) uint64 {
	return api.EncodeF64(input)
}

// DecodeF64 decodes the input as a ValueTypeF64.
//
// See EncodeF64
func DecodeF64(input uint64) float64 {
	return api.DecodeF64(input)
}
