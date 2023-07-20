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

func buildEnvModule(ctx context.Context, rt wazero.Runtime, extism api.Module) (api.Module, error) {
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

	return builder.Instantiate(ctx)
}

func configGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		name := readString(extism, ctx, offset)

		value, ok := plugin.Config[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		return writeString(extism, ctx, value)
	}

	panic("Invalid context, `plugin` key not found")
}

func varGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		name := readString(extism, ctx, offset)

		value, ok := plugin.Var[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		return writeBlock(extism, ctx, value)
	}

	panic("Invalid context, `plugin` key not found")
}

func varSet(ctx context.Context, m api.Module, nameOffset uint64, valueOffset uint64) {
	plugin, ok := ctx.Value("plugin").(*Plugin)
	if !ok {
		panic("Invalid context, `plugin` key not found")
	}

	extism := plugin.Runtime.Extism

	name := readString(extism, ctx, nameOffset)

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
		value := readBlock(extism, ctx, valueOffset)
		plugin.Var[name] = value
	}
}

func httpRequest(ctx context.Context, m api.Module, requestOffset uint64, bodyOffset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		requestJson := readBlock(extism, ctx, requestOffset)
		var request HttpRequest
		err := json.Unmarshal(requestJson, &request)
		if err != nil {
			panic(fmt.Errorf("Invalid HTTP Request: %v", err))
		}

		url, err := url.Parse(request.Url)
		if err != nil {
			panic(fmt.Errorf("Invalid Url: %v", err))
		}

		hostMatches := false
		if len(plugin.AllowedHosts) > 0 {
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
		} else {
			hostMatches = true
		}

		if !hostMatches {
			panic(fmt.Errorf("HTTP request to '%v' is not allowed", request.Url))
		}

		var bodyReader io.Reader = nil
		if bodyOffset != 0 {
			// TODO: do we need to call extism_free on the body?
			body := readBlock(extism, ctx, bodyOffset)
			bodyReader = bytes.NewReader(body)
		}

		req, err := http.NewRequest(request.Method, request.Url, bodyReader)
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
			return writeBlock(extism, ctx, body)
		}
	}

	panic("Invalid context, `plugin` key not found")
}

func httpStatusCode(ctx context.Context, m api.Module) uint32 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		return uint32(plugin.LastStatusCode)
	}

	panic("Invalid context, `plugin` key not found")
}

func writeString(extism api.Module, ctx context.Context, value string) uint64 {
	return writeBlock(extism, ctx, []byte(value))
}

func writeBlock(extism api.Module, ctx context.Context, buffer []byte) uint64 {
	res, err := extism.ExportedFunction("extism_alloc").Call(ctx, uint64(len(buffer)))
	if err != nil {
		panic(err)
	}

	out := res[0]
	mem := extism.Memory()
	mem.Write(uint32(out), buffer)

	return out
}

func readString(extism api.Module, ctx context.Context, offset uint64) string {
	return string(readBlock(extism, ctx, offset))
}

func readBlock(extism api.Module, ctx context.Context, offset uint64) []byte {
	blockLengthResult, err := extism.ExportedFunction("extism_length").Call(ctx, uint64(offset))
	if err != nil {
		panic(err)
	} else if len(blockLengthResult) != 1 {
		panic(fmt.Errorf("Expected 1 value, got %v values", len(blockLengthResult)))
	}

	blockLength := blockLengthResult[0]

	mem := extism.Memory()
	buffer, ok := mem.Read(uint32(offset), uint32(blockLength))
	if !ok {
		panic("Out of bounds read")
	}

	return buffer
}
