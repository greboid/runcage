package runtime

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Invocation struct {
	Command   string
	Global    []string
	ID        string
	Bundle    string
	Log       string
	LogFormat string
}

func globalValueFlag(name string) bool {
	switch name {
	case "log", "log-format", "root", "criu", "rootless":
		return true
	}
	return false
}

func globalBoolFlag(name string) bool {
	switch name {
	case "debug", "systemd-cgroup", "help", "h", "version", "v":
		return true
	}
	return false
}

func commandFlag(command, name string) (takesValue, known bool) {
	switch name {
	case "bundle", "b", "console-socket", "pid-file":
		return true, command != "checkpoint"
	case "pidfd-socket", "preserve-fds":
		return true, command == "create" || command == "run"
	case "image-path", "work-path", "manage-cgroups-mode", "empty-ns":
		return true, protectedCommand(command)
	case "parent-path", "page-server", "status-fd":
		return true, command == "checkpoint"
	case "lsm-profile", "lsm-mount-context":
		return true, command == "restore"
	case "leave-running", "tcp-skip-in-flight", "link-remap", "pre-dump":
		return false, command == "checkpoint"
	case "tcp-established", "ext-unix-sk", "shell-job", "lazy-pages", "file-locks", "auto-dedup":
		return false, protectedCommand(command)
	case "detach", "d", "no-subreaper", "no-pivot":
		return false, command == "restore" || command == "run" || command == "create"
	}
	return false, false
}

func protectedCommand(s string) bool { return s == "checkpoint" || s == "restore" }

func ParseArgs(args []string) (Invocation, error) {
	var inv Invocation
	i := 0
	for ; i < len(args); i++ {
		if args[i] == "--" {
			i++
			break
		}
		name, value, hasValue, ok := splitFlag(args[i])
		if !ok {
			break
		}
		if !globalValueFlag(name) && !globalBoolFlag(name) && slices.ContainsFunc(args[i+1:], protectedCommand) {
			// Its arity is unknown: even the next positional token might be a flag value.
			return inv, fmt.Errorf("cannot identify checkpoint/restore command after unknown global option %q", args[i])
		}
		if globalValueFlag(name) && !hasValue && i+1 < len(args) {
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
	if i == len(args) {
		return inv, nil
	}
	inv.Command, inv.Global = args[i], args[:i]
	strict := protectedCommand(inv.Command)
	if !strict && inv.Command != "create" && inv.Command != "run" {
		return inv, nil
	}
	operands := false
	bundleSet := false
	for i++; i < len(args); i++ {
		if !operands && args[i] == "--" {
			operands = true
			continue
		}
		name, value, hasValue, flag := splitFlag(args[i])
		if operands || !flag {
			if strict && (i != len(args)-1 || args[i] == "") {
				return inv, fmt.Errorf("%s requires exactly one trailing container ID", inv.Command)
			}
			inv.ID = args[i]
			continue
		}
		takesValue, known := commandFlag(inv.Command, name)
		if strict && !known {
			return inv, fmt.Errorf("unknown %s option %q", inv.Command, args[i])
		}
		if known && takesValue && !hasValue {
			if i+1 == len(args) || (strict && strings.HasPrefix(args[i+1], "-")) {
				return inv, fmt.Errorf("option %q requires an unambiguous value", args[i])
			}
			i++
			value = args[i]
		}
		if name == "bundle" || name == "b" {
			if strict && (bundleSet || value == "") {
				return inv, errors.New("ambiguous bundle option")
			}
			inv.Bundle, bundleSet = value, true
		}
	}
	if strict && inv.ID == "" {
		return inv, fmt.Errorf("%s requires a container ID", inv.Command)
	}
	return inv, nil
}

func splitFlag(arg string) (name, value string, hasValue, ok bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false, false
	}
	name = strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	name, value, hasValue = strings.Cut(name, "=")
	return name, value, hasValue, true
}
