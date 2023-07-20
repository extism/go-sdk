package extism

import (
	"context"
	"fmt"

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

	builder.
		NewFunctionBuilder().
		WithFunc(configGet).
		Export("extism_config_get").
		NewFunctionBuilder().
		WithFunc(varGet).
		Export("extism_var_get")

	return builder.Instantiate(ctx)
}

func configGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		mem := extism.Memory()
		name := readString(extism, ctx, mem, offset)

		value, ok := plugin.Config[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		return writeString(extism, ctx, mem, value)
	}

	panic("Invalid context, `plugin` key not found")
}

func varGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		mem := extism.Memory()
		name := readString(extism, ctx, mem, offset)

		value, ok := plugin.Var[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		return writeBlock(extism, ctx, mem, value)
	}

	panic("Invalid context, `plugin` key not found")
}

func varSet(ctx context.Context, m api.Module, nameOffset uint64, valueOffset uint64) {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		mem := extism.Memory()
		name := readString(extism, ctx, mem, nameOffset)

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
			value := readBlock(extism, ctx, mem, valueOffset)
			plugin.Var[name] = value
		}
	}

	panic("Invalid context, `plugin` key not found")
}

func writeString(extism api.Module, ctx context.Context, mem api.Memory, value string) uint64 {
	return writeBlock(extism, ctx, mem, []byte(value))
}

func writeBlock(extism api.Module, ctx context.Context, mem api.Memory, buffer []byte) uint64 {
	res, err := extism.ExportedFunction("extism_alloc").Call(ctx, uint64(len(buffer)))
	if err != nil {
		panic(err)
	}

	out := res[0]
	mem.Write(uint32(out), buffer)

	return out
}

func readString(extism api.Module, ctx context.Context, mem api.Memory, offset uint64) string {
	return string(readBlock(extism, ctx, mem, offset))
}

func readBlock(extism api.Module, ctx context.Context, mem api.Memory, offset uint64) []byte {
	blockLengthResult, err := extism.ExportedFunction("extism_length").Call(ctx, uint64(offset))
	if err != nil {
		panic(err)
	} else if len(blockLengthResult) != 1 {
		panic(fmt.Errorf("Expected 1 value, got %v values", len(blockLengthResult)))
	}

	blockLength := blockLengthResult[0]

	buffer, ok := mem.Read(uint32(offset), uint32(blockLength))
	if !ok {
		panic("Out of bounds read")
	}

	return buffer
}
