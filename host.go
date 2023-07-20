package extism

import (
	"context"

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
		Export("extism_config_get")

	return builder.Instantiate(ctx)
}

func configGet(ctx context.Context, m api.Module, offset uint64) uint64 {
	if plugin, ok := ctx.Value("plugin").(*Plugin); ok {
		extism := plugin.Runtime.Extism

		mem := extism.Memory()
		nameLengthResult, err := extism.ExportedFunction("extism_length").Call(ctx, uint64(offset))
		if err != nil {
			panic(err)
		}
		nameLength := nameLengthResult[0] // TODO: make sure it's only element

		buffer, ok := mem.Read(uint32(offset), uint32(nameLength))
		if !ok {
			panic("Out of bounds read")
		}

		name := string(buffer)
		value, ok := plugin.Config[name]
		if !ok {
			// Return 0 without an error if key is not found
			return 0
		}

		buffer = []byte(value)
		res, err := extism.ExportedFunction("extism_alloc").Call(ctx, uint64(len(buffer)))
		if err != nil {
			panic(err)
		}

		out := res[0]
		mem.Write(uint32(out), buffer)
		return out
	}

	panic("Invalid context, `plugin` key not found")
}
