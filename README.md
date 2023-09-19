# Extism Go SDK

> **Note**: This houses the 1.0 version of the Go SDK and is a work in progress. Please use the Go SDK in [extism/extism](https://github.com/extism/extism) until we hit 1.0.

This repo houses the Go SDK for integrating with the [Extism](https://extism.org/) runtime. Install this library into your host Go applications to run Extism plugins.

Join the [Discord](https://discord.gg/EGTV8Pxs) and chat with us!

## Installation

Install via `go get`:

```
go get github.com/extism/go-sdk
```

## Getting Started

The primary concept in Extism is the plug-in. You can think of a plug-in as a code module. It has imports and it has exports. These imports and exports define the interface, or your API. You decide what they are called and typed, and what they do. Then the plug-in developer implements them and you can call them.

The code for a plug-in exist as a binary wasm module. We can load this with the raw bytes or we can use the manifest to tell Extism how to load it from disk or the web.

For simplicity let's load one from the web:

```go
// NOTE: The schema for this manifest can be found here: https://extism.org/docs/concepts/manifest/
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm",
        },
    },
}

ctx := context.Background()
config := extism.PluginConfig{
    EnableWasi: true,
}

// NOTE: if you encounter an error such as:
// "Unable to load plugin: unknown import: wasi_snapshot_preview1::fd_write has not been defined"
// make sure extism.PluginConfig.EnableWasi is set to `true` to provide WASI imports to your plugin.
plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})

if err != nil {
    fmt.Printf("Failed to initialize plugin: %v\n", err)
    os.Exit(1)
}
```

This plug-in was written in C and it does one thing, it counts vowels in a string. As such it exposes one "export" function: `count_vowels`. We can call exports using `Plugin.Call`:

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
            Url: "https://raw.githubusercontent.com/extism/extism/main/wasm/code.wasm",
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

Host functions can be a complicated concept. You can think of them like custom syscalls for your plug-in. You can use them to add capabilities to your plug-in through a simple interface.

Another way to look at it is this: Up until now we've only invoked functions given to us by our plug-in, but what if our plug-in needs to invoke a function in our Go app? Host functions allow you to do this by passing a reference to a Go method to the plug-in.

Let's load up a version of count vowels with a host function:

```go
manifest := extism.Manifest{
    Wasm: []extism.Wasm{
        extism.WasmUrl{
            Url: "https://raw.githubusercontent.com/extism/extism/main/wasm/count-vowels-host.wasm",
        },
    },
}
```

Unlike our original plug-in, this plug-in expects you to provide your own implementation of "is_vowel" in Go.

First let's write our host function:

```go
hf := extism.NewHostFunctionWithStack(
    "is_vowel",
    "env",
    func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
        vowels := "AEIOUaeiou"

        result := 0

        r := rune(api.DecodeI32(stack[0]))
        if strings.ContainsRune(vowels, r) {
            result = 1
        }

        stack[0] = api.EncodeI32(int32(result))
    },

    // we need to give it the Wasm signature, it takes one i64 as input which acts as a pointer to a string
    // and it returns an i64 which is the 0 or 1 result
    []api.ValueType{api.ValueTypeI32},
    api.ValueTypeI32,
)
```

This method will be exposed to the plug-in in it's native language. We need to know the inputs and outputs and their types ahead of time. This function expects a string (single character) as the first input and expects a 0 (false) or 1 (true) in the output (returns).

We need to pass these imports to the plug-in to create them. All imports of a plug-in must be satisfied for it to be initialized:

```go
plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{hf});

exit, out, err := plugin.Call("count_vowels", []byte("Hello, World!"))

// => {"count": 3, "total": 3}
```

Although this is a trivial example, you could imagine some more elaborate APIs for host functions. This is truly how you unleash the power of the plugin. You could, for example, imagine giving the plug-in access to APIs your app normally has like reading from a database, authenticating a user, sending messages, etc.

## Build example plugins
Since our [example plugins](./plugins/) are also written in Go, for compiling them we use [TinyGo](https://tinygo.org/):
```sh
cd plugins/config
tinygo build -target wasi -o ../wasm/config.wasm main.go
```