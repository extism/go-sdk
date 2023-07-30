package main

import (
	"os"

	"github.com/extism/go-pdk"
)

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

func main() {
	content, err := updateFile("/mnt/test.txt")
	if err != nil {
		pdk.Log(pdk.LogError, err.Error())
		os.Exit(1)
	} else {
		mem := pdk.AllocateBytes(content)
		// zero-copy output to host
		pdk.OutputMemory(mem)
	}
}
