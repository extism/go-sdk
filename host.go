package extism

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	// "unsafe"

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
	module api.Module
}

func (p *Plugin) currentPlugin(module api.Module) *CurrentPlugin {
	return &CurrentPlugin{p, module}
}

func (p *CurrentPlugin) Log(level LogLevel, message string) {
	p.plugin.Log(level, message)
}

func (p *CurrentPlugin) Logf(level LogLevel, format string, args ...any) {
	p.plugin.Logf(level, format, args...)
}

// Memory returns the plugin's WebAssembly memory interface.
func (p *CurrentPlugin) Memory() api.Memory {
	return p.module.Memory()
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

		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
				closure(ctx, &CurrentPlugin{plugin, m}, stack)
				return
			}

			panic("Invalid context, `plugin` key not found")
		}), f.Params, f.Returns).Export(f.Name)
	}
}

func buildEnvModule(ctx context.Context, rt wazero.Runtime) (api.Module, error) {
	builder := rt.NewHostModuleBuilder("extism:host/env")

	hostFunc := func(name string, f interface{}) {
		builder.NewFunctionBuilder().WithFunc(f).Export(name)
	}

	hostFunc("read", read)
	hostFunc("bytes_remaining", bytesRemaining)
	hostFunc("write", write)
	hostFunc("config_read", configRead)
	hostFunc("config_length", configLength)
	hostFunc("stack_push", stackPush)
	hostFunc("stack_pop", stackPop)

	hostFunc("error", func(ctx context.Context, m api.Module, handle uint64) {
		offs, len := getHandle(handle)
		data, ok := m.Memory().Read(offs, len)
		if !ok {
			panic("invalid memory in call to extism:host/env::error")
		}
		panic(string(data))
	})
	// hostFunc("http_request", httpRequest)
	hostFunc("http_status_code", httpStatusCode)
	// hostFunc("http_body", httpBody)

	hostFunc("log", func(ctx context.Context, m api.Module, level uint32, handle uint64) {
		offs, len := getHandle(handle)
		data, ok := m.Memory().Read(offs, len)
		if !ok {
			panic(fmt.Errorf("Failed to read log message from memory"))
		}
		if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
			plugin.Log(LogLevel(level+2), string(data))
			return
		}

		panic("Invalid context, `plugin` key not found")
	})

	return builder.Instantiate(ctx)
}

func getHandle(h uint64) (uint32, uint32) {
	size := h & 0xffffffff
	offs := (h >> 32) & 0xffffffff
	return uint32(offs), uint32(size)
}

func stackPush(ctx context.Context, m api.Module) {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		plugin.Input.push()
		plugin.Output.push()
	}
}

func stackPop(ctx context.Context, m api.Module) {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		plugin.Input.pop()
		plugin.Output.pop()
	}
}

func read(ctx context.Context, m api.Module, stream int32, handle uint64) int64 {
	offs, len := getHandle(handle)
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		buf, ok := m.Memory().Read(offs, len)
		if !ok {
			panic("Invalid offset in input_read")
		}
		var p pipeQueue
		if stream == 0 {
			p = plugin.Input
		} else {
			p = plugin.Output
		}
		n, err := p.current().read(buf)
		if err == io.EOF {
			return -1
		}
		if err != nil {
			panic(err)
		}
		return int64(n)
	}

	return -1
}

func bytesRemaining(ctx context.Context, m api.Module, stream int32) int64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		var p pipeQueue
		if stream == 0 {
			p = plugin.Input
		} else {
			p = plugin.Output
		}
		n := len(p.current().data)
		return int64(n)
	}

	return -1
}

func write(ctx context.Context, m api.Module, stream int32, handle uint64) int64 {
	offs, len := getHandle(handle)
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		buf, ok := m.Memory().Read(offs, len)
		if !ok {
			panic("Invalid offset in output_write")
		}
		var p pipeQueue
		if stream == 0 {
			p = plugin.Input
		} else {
			p = plugin.Output
		}
		n, _ := p.current().write(buf)
		return int64(n)
	}
	return -1
}

func configRead(ctx context.Context, m api.Module, handle uint64, outhandle uint64) int64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		offs, len := getHandle(handle)
		name, ok := m.Memory().Read(offs, len)
		if !ok {
			panic(fmt.Errorf("Failed to read config name from memory"))
		}

		value, ok := plugin.Config[string(name)]
		if !ok {
			// Return 0 without an error if key is not found
			return -1
		}

		offs, len = getHandle(outhandle)
		m.Memory().WriteString(offs, value)
		return int64(len)
	}

	panic("Invalid context, `plugin` key not found")
}

func configLength(ctx context.Context, m api.Module, handle uint64) int64 {
	offs, length := getHandle(handle)
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		name, ok := m.Memory().Read(offs, length)
		if !ok {
			panic(fmt.Errorf("Failed to read config name from memory"))
		}

		value, ok := plugin.Config[string(name)]
		if !ok {
			// Return 0 without an error if key is not found
			return -1
		}

		return int64(len(value))
	}
	panic("Invalid context, `plugin` key not found")
}

func httpRequest(ctx context.Context, m api.Module, requestHandle uint64, bodyHandle uint64) int64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		requestOffs, requestLen := getHandle(requestHandle)
		bodyOffs, bodyLen := getHandle(bodyHandle)

		requestJson, ok := m.Memory().Read(requestOffs, requestLen)
		if !ok {
			panic("Invalid memory handle in http request")
		}
		var request HttpRequest
		err := json.Unmarshal(requestJson, &request)
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
		if bodyHandle != 0 {
			body, ok := m.Memory().Read(bodyOffs, bodyLen)
			if !ok {
				panic("Failed to read response body from memory")
			}

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
		plugin.LastResponseBody = bytes.NewBuffer(body)

		n := len(body)

		return int64(n)
	}

	panic("Invalid context, `plugin` key not found")
}

func httpBody(ctx context.Context, m api.Module, handle uint64) int64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		offs, len := getHandle(handle)
		data, ok := m.Memory().Read(offs, len)
		if !ok {
			return -1
		}
		n, err := plugin.LastResponseBody.Read(data)
		if err == io.EOF && n == 0 {
			return -1
		} else if err != nil {
			panic(err)
		}
		return int64(n)
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
