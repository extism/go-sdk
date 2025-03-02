# standard go compiler, command module
GOOS=wasip1 GOARCH=wasm go build -tags std -o ../../wasm/std_command.wasm .