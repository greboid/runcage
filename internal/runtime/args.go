package runtime

import "strings"

type Invocation struct {
	Command string
	// Arguments before the command.
	Global []string
	// Last positional argument.
	ID        string
	Bundle    string
	Log       string
	LogFormat string
}

var globalValueFlags = map[string]bool{
	"log":        true,
	"log-format": true,
	"root":       true,
	"criu":       true,
	"rootless":   true,
}

var commandValueFlags = map[string]bool{
	"bundle":              true,
	"b":                   true,
	"console-socket":      true,
	"pid-file":            true,
	"preserve-fds":        true,
	"image-path":          true,
	"work-path":           true,
	"parent-path":         true,
	"page-server":         true,
	"manage-cgroups-mode": true,
	"empty-ns":            true,
	"status-fd":           true,
	"lsm-profile":         true,
	"lsm-mount-context":   true,
}

func ParseArgs(args []string) Invocation {
	var inv Invocation
	i := 0
	for ; i < len(args); i++ {
		name, value, hasValue, ok := splitFlag(args[i])
		if !ok {
			inv.Command = args[i]
			inv.Global = args[:i]
			break
		}
		if globalValueFlags[name] && !hasValue && i+1 < len(args) {
			i++
			value = args[i]
		}
		switch name {
		case "log":
			inv.Log = value
		case "log-format":
			inv.LogFormat = value
		}
	}
	for i++; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		name, value, hasValue, ok := splitFlag(args[i])
		if !ok {
			inv.ID = args[i]
			continue
		}
		if commandValueFlags[name] && !hasValue && i+1 < len(args) {
			i++
			value = args[i]
		}
		if name == "bundle" || name == "b" {
			inv.Bundle = value
		}
	}
	return inv
}

func splitFlag(arg string) (name, value string, hasValue, ok bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false, false
	}
	name = strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	name, value, hasValue = strings.Cut(name, "=")
	return name, value, hasValue, true
}
