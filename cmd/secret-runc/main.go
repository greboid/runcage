package main

import (
	"os"

	"g5d.dev/runcage/internal/injection"
	"g5d.dev/runcage/internal/runtime"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == injection.HookCommand {
		os.Exit(injection.Main(os.Args[2:], os.Stdin, os.Stderr))
	}
	os.Exit(runtime.Main(os.Args[1:]))
}
