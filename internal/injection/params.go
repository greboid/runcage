package injection

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	HookCommand = "hook"

	CreateRuntimeHook   = "create-runtime"
	CreateContainerHook = "create-container"

	SecretsDir = "/run/secrets"
	// secret-env's limit.
	MaxNameLength = 255
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ValidName(name string) bool {
	return len(name) <= MaxNameLength && namePattern.MatchString(name)
}

type Params struct {
	Source string
	Rootfs string
	UID    uint32
	GID    uint32
	// Empty selects all.
	Keys []string
}

func (p Params) Args(hook string) []string {
	return []string{
		"secret-runc", HookCommand, hook,
		"--source=" + p.Source,
		"--rootfs=" + p.Rootfs,
		"--owner=" + FormatOwner(p.UID, p.GID),
		"--keys=" + strings.Join(p.Keys, ","),
	}
}

func ParseParams(args []string) (Params, error) {
	var p Params
	var owner, keys string
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&p.Source, "source", "", "")
	fs.StringVar(&p.Rootfs, "rootfs", "", "")
	fs.StringVar(&owner, "owner", "", "")
	fs.StringVar(&keys, "keys", "", "")
	if err := fs.Parse(args); err != nil {
		return p, err
	}
	if fs.NArg() != 0 {
		return p, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if !filepath.IsAbs(p.Source) || !filepath.IsAbs(p.Rootfs) {
		return p, errors.New("source and rootfs must be absolute")
	}
	var err error
	if p.UID, p.GID, err = ParseOwner(owner); err != nil {
		return p, err
	}
	if p.Keys, err = ParseKeys(keys); err != nil {
		return p, err
	}
	return p, nil
}

func ParseOwner(s string) (uid, gid uint32, err error) {
	u, g, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, fmt.Errorf("invalid owner %q: want uid:gid", s)
	}
	if uid, err = parseID(u); err != nil {
		return 0, 0, fmt.Errorf("invalid owner %q: %w", s, err)
	}
	if gid, err = parseID(g); err != nil {
		return 0, 0, fmt.Errorf("invalid owner %q: %w", s, err)
	}
	return uid, gid, nil
}

func parseID(s string) (uint32, error) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 1<<32-1 {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	return uint32(n), nil
}

func FormatOwner(uid, gid uint32) string {
	return fmt.Sprintf("%d:%d", uid, gid)
}

func ParseKeys(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var keys []string
	for k := range strings.SplitSeq(s, ",") {
		k = strings.TrimSpace(k)
		if !ValidName(k) {
			return nil, fmt.Errorf("invalid key %q", k)
		}
		if seen[k] {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys, nil
}

func Select(values map[string][]byte, keys []string) (map[string][]byte, error) {
	if len(keys) == 0 {
		return values, nil
	}
	out := make(map[string][]byte, len(keys))
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			return nil, fmt.Errorf("key %q not in document", k)
		}
		out[k] = v
	}
	return out, nil
}
