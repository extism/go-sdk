package main

import (
	"os"
	"strconv"

	"github.com/extism/go-pdk"
)

func main() {
	if config, ok := pdk.GetConfig("code"); ok {
		if code, err := strconv.Atoi(config); err == nil {
			os.Exit(code)
		} else {
			os.Exit(1)
		}
	} else {
		os.Exit(2)
	}
}
