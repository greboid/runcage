package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"g5d.dev/runcage/internal/injection"
)

const (
	sopsDir = "/run/sops"

	annotationPrefix = "com.greboid.secrets."
	annotationKeys   = annotationPrefix + "keys"
	annotationOwner  = annotationPrefix + "owner"

	// noswap needs Linux 6.4+.
	tmpfsOptions = "nosuid,nodev,noexec,mode=0755,size=4m,nr_inodes=1024,noswap"

	createRuntimeTimeout   = 60
	createContainerTimeout = 10
)

type StatFunc func(string) (os.FileInfo, error)

func PrepareBundle(bundle, self string) error {
	if bundle == "" {
		bundle = "."
	}
	bundle, err := filepath.Abs(bundle)
	if err != nil {
		return fmt.Errorf("cannot resolve bundle: %w", err)
	}
	configPath := filepath.Join(bundle, "config.json")
	info, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("cannot stat config: %w", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("cannot read config: %w", err)
	}
	out, changed, err := Rewrite(data, bundle, self, os.Stat)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return writeAtomic(configPath, out, info.Mode().Perm())
}

// Preserves untouched fields, including unknown ones.
func Rewrite(data []byte, bundle, self string, stat StatFunc) ([]byte, bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("invalid config: %w", err)
	}
	var rawMounts []json.RawMessage
	if err := unmarshalField(raw, "mounts", &rawMounts); err != nil {
		return nil, false, err
	}
	mounts := make([]specs.Mount, len(rawMounts))
	for i, m := range rawMounts {
		if err := json.Unmarshal(m, &mounts[i]); err != nil {
			return nil, false, fmt.Errorf("invalid mount: %w", err)
		}
	}
	var rawHooks map[string]json.RawMessage
	if err := unmarshalField(raw, "hooks", &rawHooks); err != nil {
		return nil, false, err
	}
	var hooks specs.Hooks
	if err := unmarshalField(raw, "hooks", &hooks); err != nil {
		return nil, false, err
	}
	var annotations map[string]string
	if err := unmarshalField(raw, "annotations", &annotations); err != nil {
		return nil, false, err
	}

	marker, err := findMarker(mounts, stat)
	if err != nil {
		return nil, false, err
	}
	if marker < 0 {
		return data, false, nil
	}
	if hasOwnHooks(hooks, self) {
		return nil, false, errors.New("config already has secret hooks and a SOPS document")
	}

	var spec struct {
		Root    *specs.Root    `json:"root"`
		Process *specs.Process `json:"process"`
		Linux   *specs.Linux   `json:"linux"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, false, fmt.Errorf("invalid config: %w", err)
	}
	if spec.Linux != nil && slices.ContainsFunc(spec.Linux.Namespaces, func(ns specs.LinuxNamespace) bool {
		return ns.Type == specs.UserNamespace
	}) {
		return nil, false, errors.New("secrets are not supported with user namespaces")
	}
	if spec.Root == nil || spec.Root.Path == "" {
		return nil, false, errors.New("config has no root path")
	}
	params, err := buildParams(annotations, spec.Process, mounts[marker].Source, bundle, spec.Root.Path)
	if err != nil {
		return nil, false, err
	}

	rawMounts = slices.Delete(rawMounts, marker, marker+1)
	tmpfs, err := json.Marshal(specs.Mount{
		Destination: injection.SecretsDir,
		Type:        "tmpfs",
		Source:      "tmpfs",
		Options:     strings.Split(tmpfsOptions, ","),
	})
	if err != nil {
		return nil, false, err
	}
	rawMounts = append(rawMounts, tmpfs)
	if err := setField(raw, "mounts", rawMounts); err != nil {
		return nil, false, err
	}

	if rawHooks == nil {
		rawHooks = map[string]json.RawMessage{}
	}
	if err := appendHook(rawHooks, "createRuntime", specs.Hook{
		Path:    self,
		Args:    params.Args(injection.CreateRuntimeHook),
		Timeout: new(createRuntimeTimeout),
	}); err != nil {
		return nil, false, err
	}
	if err := appendHook(rawHooks, "createContainer", specs.Hook{
		Path:    self,
		Args:    params.Args(injection.CreateContainerHook),
		Timeout: new(createContainerTimeout),
	}); err != nil {
		return nil, false, err
	}
	if err := setField(raw, "hooks", rawHooks); err != nil {
		return nil, false, err
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func HasSecrets(data []byte, self string, stat StatFunc) (bool, error) {
	var spec struct {
		Mounts []specs.Mount `json:"mounts"`
		Hooks  *specs.Hooks  `json:"hooks"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return false, fmt.Errorf("invalid config: %w", err)
	}
	if spec.Hooks != nil && hasOwnHooks(*spec.Hooks, self) {
		return true, nil
	}
	for _, m := range spec.Mounts {
		if under(path.Clean(m.Destination), sopsDir) {
			return true, nil
		}
	}
	return false, nil
}

func findMarker(mounts []specs.Mount, stat StatFunc) (int, error) {
	marker := -1
	var conflict string
	for i, m := range mounts {
		dest := path.Clean(m.Destination)
		switch {
		case under(dest, injection.SecretsDir):
			conflict = dest
		case path.Dir(dest) == sopsDir && isBind(m):
			if marker >= 0 {
				return -1, fmt.Errorf("more than one document under %s", sopsDir)
			}
			marker = i
		case under(dest, sopsDir):
			return -1, fmt.Errorf("unsupported mount at %s", dest)
		}
	}
	if marker < 0 {
		return -1, nil
	}
	if conflict != "" {
		return -1, fmt.Errorf("existing mount at %s conflicts with %s", conflict, injection.SecretsDir)
	}
	src := mounts[marker].Source
	if !filepath.IsAbs(src) {
		return -1, fmt.Errorf("document source %q is not absolute", src)
	}
	info, err := stat(src)
	if err != nil {
		return -1, fmt.Errorf("cannot stat document: %w", err)
	}
	if !info.Mode().IsRegular() {
		return -1, fmt.Errorf("document %s is not a regular file", src)
	}
	return marker, nil
}

func buildParams(annotations map[string]string, process *specs.Process, source, bundle, root string) (injection.Params, error) {
	p := injection.Params{Source: source, Rootfs: root}
	if !filepath.IsAbs(p.Rootfs) {
		p.Rootfs = filepath.Join(bundle, p.Rootfs)
	}
	p.Rootfs = filepath.Clean(p.Rootfs)
	for k := range annotations {
		if strings.HasPrefix(k, annotationPrefix) && k != annotationKeys && k != annotationOwner {
			return p, fmt.Errorf("unknown annotation %s", k)
		}
	}
	var err error
	if v, ok := annotations[annotationKeys]; ok {
		if p.Keys, err = injection.ParseKeys(v); err != nil {
			return p, fmt.Errorf("annotation %s: %w", annotationKeys, err)
		}
		if p.Keys == nil {
			return p, fmt.Errorf("annotation %s is empty", annotationKeys)
		}
	}
	if v, ok := annotations[annotationOwner]; ok {
		if p.UID, p.GID, err = injection.ParseOwner(v); err != nil {
			return p, fmt.Errorf("annotation %s: %w", annotationOwner, err)
		}
	} else {
		if process == nil {
			return p, errors.New("config has no process")
		}
		p.UID, p.GID = process.User.UID, process.User.GID
	}
	return p, nil
}

func hasOwnHooks(h specs.Hooks, self string) bool {
	own := func(hook specs.Hook) bool {
		return hook.Path == self && len(hook.Args) > 1 && hook.Args[1] == injection.HookCommand
	}
	return slices.ContainsFunc(h.CreateRuntime, own) || slices.ContainsFunc(h.CreateContainer, own)
}

func isBind(m specs.Mount) bool {
	return m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind")
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

func unmarshalField(raw map[string]json.RawMessage, key string, v any) error {
	data, ok := raw[key]
	if !ok || string(data) == "null" {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("invalid config %s: %w", key, err)
	}
	return nil
}

func setField(raw map[string]json.RawMessage, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw[key] = data
	return nil
}

func appendHook(hooks map[string]json.RawMessage, name string, hook specs.Hook) error {
	var list []json.RawMessage
	if err := unmarshalField(hooks, name, &list); err != nil {
		return err
	}
	data, err := json.Marshal(hook)
	if err != nil {
		return err
	}
	return setField(hooks, name, append(list, data))
}

func writeAtomic(name string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".config.json.*")
	if err != nil {
		return fmt.Errorf("cannot write config: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("cannot write config: %w", err)
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("cannot write config: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("cannot write config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot write config: %w", err)
	}
	if err := os.Rename(tmp, name); err != nil {
		return fmt.Errorf("cannot write config: %w", err)
	}
	return nil
}
