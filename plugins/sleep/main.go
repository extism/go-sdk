package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/extism/go-pdk"
)

//export run_test
func run_test() int32 {
	config, _ := pdk.GetConfig("duration")
	seconds, _ := strconv.Atoi(config)

	duration := time.Duration(seconds) * time.Second
	now := time.Now()

	// time.Sleep() doesn't work here
	for time.Now().Before(now.Add(duration)) {
		// busy loop
	}

	mem := pdk.AllocateString(fmt.Sprintf("slept for %v seconds", seconds))

	// zero-copy output to host
	pdk.OutputMemory(mem)

	return 0
}

func main() {}
