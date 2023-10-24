# Extism Go SDK

This repo houses the Go SDK for integrating with the [Extism](https://extism.org/) runtime. Install this library into your host Go applications to run Extism plugins.

Join the [Discord](https://discord.gg/EGTV8Pxs) and chat with us!

## Installation

Install via `go get`:

```
go get github.com/extism/go-sdk
```

## Getting Started

This guide should walk you through some of the concepts in Extism and this Go library.

### Creating A Plug-in

The primary concept in Extism is the [plug-in](https://extism.org/docs/concepts/plug-in). You can think of a plug-in as a code module stored in a `.wasm` file.

Plug-in code can come from a file on disk, object storage or any number of places. Since you may not have one handy let's load a demo plug-in from the web:

```go
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels.wasm",
        },
    },
}

ctx := context.Background()
config := extism.PluginConfig{
    EnableWasi: true,
}

plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

if err != nil {
    fmt.Printf("Failed to initialize plugin: %v\n", err)
    os.Exit(1)
}
```
> **Note**: See [the Manifest docs](https://pkg.go.dev/github.com/extism/go-sdk#Manifest) as it has a rich schema and a lot of options.

### Calling A Plug-in's Exports

This plug-in was written in Rust and it does one thing, it counts vowels in a string. As such, it exposes one "export" function: `count_vowels`. We can call exports using [extism.Plugin.Call](https://pkg.go.dev/github.com/extism/go-sdk#Plugin.Call):

```go
exit, out, err := plugin.Call("count_vowels", data)
if err != nil {
    fmt.Println(err)
    os.Exit(int(exit))
}

response := string(out)

// => {"count": 3, "total": 3, "vowels": "aeiouAEIOU"}
```

All exports have a simple interface of optional bytes in, and optional bytes out. This plug-in happens to take a string and return a JSON encoded string with a report of results.

### Plug-in State

Plug-ins may be stateful or stateless. Plug-ins can maintain state b/w calls by the use of variables. Our count vowels plug-in remembers the total number of vowels it's ever counted in the "total" key in the result. You can see this by making subsequent calls to the export:

```go
exit, out, err := plugin.Call("count_vowels", []byte("Hello, World!"))
if err != nil {
    fmt.Println(err)
    os.Exit(int(exit))
}
// => {"count": 3, "total": 6, "vowels": "aeiouAEIOU"}

exit, out, err = plugin.Call("count_vowels", []byte("Hello, World!"))
if err != nil {
    fmt.Println(err)
    os.Exit(int(exit))
}
// => {"count": 3, "total": 9, "vowels": "aeiouAEIOU"}
```

These variables will persist until this plug-in is freed or you initialize a new one.

### Configuration

Plug-ins may optionally take a configuration object. This is a static way to configure the plug-in. Our count-vowels plugin takes an optional configuration to change out which characters are considered vowels. Example:

```go
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels.wasm",
        },
    },
    Config: map[string]string{
        "vowels": "aeiouyAEIOUY",
    },
}

ctx := context.Background()
config := extism.PluginConfig{
    EnableWasi: true,
}

plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

if err != nil {
    fmt.Printf("Failed to initialize plugin: %v\n", err)
    os.Exit(1)
}

exit, out, err := plugin.Call("count_vowels", []byte("Yellow, World!"))
if err != nil {
    fmt.Println(err)
    os.Exit(int(exit))
}
// => {"count": 4, "total": 4, "vowels": "aeiouAEIOUY"}
```

### Host Functions

Let's extend our count-vowels example a little bit: Instead of storing the `total` in an ephemeral plug-in var, let's store it in a persistent key-value store!

Wasm can't use our KV store on it's own. This is where [Host Functions](https://extism.org/docs/concepts/host-functions) come in.

[Host functions](https://extism.org/docs/concepts/host-functions) allow us to grant new capabilities to our plug-ins from our application. They are simply some Go functions you write which can be passed down and invoked from any language inside the plug-in.

Let's load the manifest like usual but load up this `count_vowels_kvstore` plug-in:

```go
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://github.com/extism/plugins/releases/latest/download/count_vowels_kvstore.wasm",
        },
    },
}
```

> *Note*: The source code for this is [here](https://github.com/extism/plugins/blob/main/count_vowels_kvstore/src/lib.rs) and is written in rust, but it could be written in any of our PDK languages.

Unlike our previous plug-in, this plug-in expects you to provide host functions that satisfy our its import interface for a KV store.

We want to expose two functions to our plugin, `kv_write(key string, value []bytes)` which writes a bytes value to a key and `kv_read(key string) []byte` which reads the bytes at the given `key`.
```go
// pretend this is Redis or something :)
kvStore := make(map[string][]byte)

kvRead := extism.NewHostFunctionWithStack(
    "kv_read",
    "env",
    func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
        key, err := p.ReadString(stack[0])
        if err != nil {
            panic(err)
        }

        value, success := kvStore[key]
        if !success {
            value = []byte{0, 0, 0, 0}
        }

        fmt.Printf("Read %v from key=%s\n", binary.LittleEndian.Uint32(value), key)
        stack[0], err = p.WriteBytes(value)
    },
    []api.ValueType{api.ValueTypeI64},
    []api.ValueType{api.ValueTypeI64},
)

kvWrite := extism.NewHostFunctionWithStack(
    "kv_write",
    "env",
    func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
        key, err := p.ReadString(stack[0])
        if err != nil {
            panic(err)
        }

        value, err := p.ReadBytes(stack[1])
        if err != nil {
            panic(err)
        }

        fmt.Printf("Writing value=%v from key=%s\n", binary.LittleEndian.Uint32(value), key)

        kvStore[key] = value
    },
    []api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
    []api.ValueType{},
)
```

> *Note*: In order to write host functions you should get familiar with the methods on the [extism.CurrentPlugin](https://pkg.go.dev/github.com/extism/go-sdk#CurrentPlugin) type. The `p` parameter is an instance of this type.

We need to pass these imports to the plug-in to create them. All imports of a plug-in must be satisfied for it to be initialized:

```go
plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{kvRead, kvWrite});
```

Now we can invoke the event:

```go
exit, out, err := plugin.Call("count_vowels", []byte("Hello, World!"))
// => Read from key=count-vowels"
// => Writing value=3 from key=count-vowels"
// => {"count": 3, "total": 3, "vowels": "aeiouAEIOU"}

exit, out, err = plugin.Call("count_vowels", []byte("Hello, World!"))
// => Read from key=count-vowels"
// => Writing value=6 from key=count-vowels"
// => {"count": 3, "total": 6, "vowels": "aeiouAEIOU"}
```

## Build example plugins
Since our [example plugins](./plugins/) are also written in Go, for compiling them we use [TinyGo](https://tinygo.org/):
```sh
cd plugins/config
tinygo build -target wasi -o ../wasm/config.wasm main.go
```
