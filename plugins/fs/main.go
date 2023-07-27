package main

import (
	"os"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {

	content, err := updateFile("/mnt/test.txt")
	if err != nil {
		pdk.Log(pdk.LogError, err.Error())
		return 1
	} else {
		mem := pdk.AllocateBytes(content)
		// zero-copy output to host
		pdk.OutputMemory(mem)
	}

	return 0
}

func updateFile(filename string) ([]byte, error) {
	// Read the file and get its contents as a byte slice
	content, err := os.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}

	// Write to the file, just to prove that we can
	err = os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		return []byte{}, err
	}

	return content, nil
}

func main() {}
