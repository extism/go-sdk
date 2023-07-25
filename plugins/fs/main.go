package main

import (
	"os"
	"strings"
	"time"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {

	content, err := updateFile("/hello.txt")
	if err != nil {
		pdk.Log(pdk.LogError, err.Error())
		return 1
	} else {
		mem := pdk.AllocateString("Success: " + content)
		// zero-copy output to host
		pdk.OutputMemory(mem)
	}

	return 0
}

func updateFile(filename string) (string, error) {
	// Read the file and get its contents as a byte slice
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a string
	lines := strings.Split(string(content), "\n")

	// Get the current timestamp
	currentTimestamp := time.Now().Format(time.RFC3339)

	// Modify the last line with the "last updated" information
	if len(lines) > 0 {
		lines[len(lines)-1] = "last updated: " + currentTimestamp
	}

	// Join the lines back into a single string
	updatedContent := strings.Join(lines, "\n")

	// Write the updated content back to the file, overwriting its previous content
	err = os.WriteFile(filename, []byte(updatedContent), 0644)
	if err != nil {
		return "", err
	}

	return updatedContent, nil
}

func main() {}
