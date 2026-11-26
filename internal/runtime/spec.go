package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	annotationPrefix  = "g5d.dev/runcage/"
	annotationKeys    = annotationPrefix + "keys"
	annotationOwner   = annotationPrefix + "owner"
	annotationSecrets = annotationPrefix + "secrets"
	secretsPresent    = "present"
	secretsAbsent     = "absent"

	// noswap needs Linux 6.4+.
	tmpfsOptions = "nosuid,nodev,noexec,mode=0755,size=4m,nr_inodes=1024,noswap"

	createRuntimeTimeout   = 60
	createContainerTimeout = 10
)

type StatFunc func(string) (os.FileInfo, error)

func PrepareBundle(bundle, self string) error {
	return prepareBundle(bundle, self, false)
}

func prepareBundle(bundle, self string, restoring bool) error {
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
	if restoring {
		has, err := HasSecrets(data)
		if err != nil {
			return err
		}
		if has {
			return errCheckpoint
		}
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
	raw, err := configFields(data)
	if err != nil {
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

	for k := range annotations {
		if strings.HasPrefix(k, annotationSecrets+"=") {
			return nil, false, fmt.Errorf("invalid annotation name %q", k)
		}
	}
	marker, err := findMarker(mounts, stat)
	if err != nil {
		return nil, false, err
	}
	if marker < 0 {
		if !hasSecretArtifacts(mounts, hooks) || annotations[annotationSecrets] == secretsPresent {
			return data, false, nil
		}
		return stampConfig(raw, annotations, secretsPresent)
	}
	if hasSecretHooks(hooks) {
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

	return stampConfig(raw, annotations, secretsPresent)
}

func stampConfig(raw map[string]json.RawMessage, annotations map[string]string, classification string) ([]byte, bool, error) {
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[annotationSecrets] = classification
	if err := setField(raw, "annotations", annotations); err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(raw)
	return out, err == nil, err
}

func markedSecrets(annotations map[string]string) bool {
	v, ok := annotations[annotationSecrets]
	return ok && v != secretsAbsent
}

func HasSecrets(data []byte) (bool, error) {
	var spec struct {
		Mounts      []specs.Mount     `json:"mounts"`
		Hooks       specs.Hooks       `json:"hooks"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return false, fmt.Errorf("invalid config: %w", err)
	}
	return markedSecrets(spec.Annotations) || hasSecretArtifacts(spec.Mounts, spec.Hooks), nil
}

func hasSecretArtifacts(mounts []specs.Mount, hooks specs.Hooks) bool {
	return hasSecretHooks(hooks) || slices.ContainsFunc(mounts, func(m specs.Mount) bool {
		dest := path.Clean(m.Destination)
		return under(dest, sopsDir) || (dest == injection.SecretsDir && m.Type == "tmpfs" && slices.Contains(m.Options, "noswap"))
	})
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
		if strings.HasPrefix(k, annotationPrefix) && k != annotationKeys && k != annotationOwner && k != annotationSecrets {
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

func hasSecretHooks(h specs.Hooks) bool {
	own := func(hook specs.Hook) bool {
		return len(hook.Args) >= 3 && hook.Args[1] == injection.HookCommand &&
			(hook.Args[2] == injection.CreateRuntimeHook || hook.Args[2] == injection.CreateContainerHook)
	}
	return slices.ContainsFunc(h.CreateRuntime, own) || slices.ContainsFunc(h.CreateContainer, own)
}

func isBind(m specs.Mount) bool {
	return m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind")
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// runc matches field names case-insensitively; reject variants it could read differently.
func configFields(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected config object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		key := tok.(string)
		for _, canonical := range []string{"mounts", "hooks", "annotations"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return nil, fmt.Errorf("noncanonical config field %q", key)
			}
		}
		if _, ok := fields[key]; ok {
			return nil, fmt.Errorf("duplicate config field %q", key)
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		fields[key] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after config object")
	}
	return fields, nil
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
