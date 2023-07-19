package extism

import (
	"context"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func buildEnvModule(ctx context.Context, rt wazero.Runtime, extism api.Module) (api.Module, error) {
	builder := rt.NewHostModuleBuilder("env")
	builder.
		NewFunctionBuilder().
		WithFunc(func(length uint64) uint64 {
			f := extism.ExportedFunction("extism_alloc")
			res, err := f.Call(ctx, length)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_alloc")

	builder.
		NewFunctionBuilder().
		WithFunc(func(length uint64) uint64 {
			f := extism.ExportedFunction("extism_free")
			res, err := f.Call(ctx, length)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_free")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) uint64 {
			f := extism.ExportedFunction("extism_load_u64")
			res, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_load_u64")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) uint32 {
			f := extism.ExportedFunction("extism_load_u8")
			res, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}

			return uint32(res[0])
		}).
		Export("extism_load_u8")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) uint64 {
			f := extism.ExportedFunction("extism_input_load_u64")
			res, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_input_load_u64")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) uint32 { // NOTE: uint8 is not supported by wazero
			f := extism.ExportedFunction("extism_input_load_u8")
			res, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}

			return uint32(res[0])
		}).
		Export("extism_input_load_u8")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64, x uint32) { // NOTE: uint8 is not supported by wazero
			f := extism.ExportedFunction("extism_store_u8")
			_, err := f.Call(ctx, offset, uint64(x))
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_store_u8")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64, x uint64) {
			f := extism.ExportedFunction("extism_store_u64")
			_, err := f.Call(ctx, offset, x)
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_store_u64")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64, length uint64) {
			f := extism.ExportedFunction("extism_input_set")
			_, err := f.Call(ctx, length)
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_input_set")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64, length uint64) {
			f := extism.ExportedFunction("extism_output_set")
			_, err := f.Call(ctx, offset, length)
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_output_set")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_input_length")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_input_length")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_input_offset")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_input_offset")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_output_length")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_output_length")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_output_offset")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_output_offset")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) uint64 {
			f := extism.ExportedFunction("extism_length")
			res, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_length")

	builder.
		NewFunctionBuilder().
		WithFunc(func() {
			f := extism.ExportedFunction("extism_reset")
			_, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_reset")

	builder.
		NewFunctionBuilder().
		WithFunc(func(offset uint64) {
			f := extism.ExportedFunction("extism_error_set")
			_, err := f.Call(ctx, offset)
			if err != nil {
				panic(err)
			}
		}).
		Export("extism_error_set")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_error_get")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_error_get")

	builder.
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			f := extism.ExportedFunction("extism_memory_bytes")
			res, err := f.Call(ctx)
			if err != nil {
				panic(err)
			}

			return res[0]
		}).
		Export("extism_memory_bytes")

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
