package runtime

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"g5d.dev/runcage/internal/injection"
)

const self = "/usr/bin/runcage"

type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "f" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func fakeStat(p string) (os.FileInfo, error) {
	if strings.HasSuffix(p, "/dir") {
		return fakeInfo{fs.ModeDir}, nil
	}
	return fakeInfo{0}, nil
}

func sopsMount(dest string) map[string]any {
	return map[string]any{
		"destination": dest,
		"type":        "bind",
		"source":      "/srv/app/secrets.sops.yaml",
		"options":     []string{"rbind", "rro", "rprivate"},
	}
}

func baseConfig(mounts ...map[string]any) map[string]any {
	all := []any{
		map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
	}
	for _, m := range mounts {
		all = append(all, m)
	}
	return map[string]any{
		"ociVersion": "1.3.0",
		"root":       map[string]any{"path": "rootfs"},
		"process":    map[string]any{"user": map[string]any{"uid": 1000, "gid": 1001}, "args": []string{"sh"}, "cwd": "/"},
		"mounts":     all,
		"hooks": map[string]any{
			"createRuntime": []any{map[string]any{"path": "/usr/bin/other", "args": []string{"other"}}},
		},
		"linux":        map[string]any{"namespaces": []any{map[string]any{"type": "mount"}}},
		"futureField":  map[string]any{"kept": true},
		"annotations":  map[string]string{},
		"unknownSlice": []int{1, 2},
	}
}

func rewrite(t *testing.T, cfg map[string]any) ([]byte, bool, error) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return Rewrite(data, "/run/bundle", self, fakeStat)
}

func TestRewritePlainClassification(t *testing.T) {
	cfg := baseConfig()
	out, changed, err := rewrite(t, cfg)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	cfg["annotations"] = map[string]string{annotationSecrets: secretsAbsent}
	want, _ := json.Marshal(cfg)
	if string(out) != string(want) {
		t.Fatal("plain rewrite changed more than the classification")
	}
	again, changed, err := Rewrite(out, "/run/bundle", self, fakeStat)
	if err != nil || changed || string(out) != string(again) {
		t.Fatalf("plain rewrite not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestRewriteMarker(t *testing.T) {
	out, changed, err := rewrite(t, baseConfig(sopsMount("/run/sops/secrets.yaml")))
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(out, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Annotations[annotationSecrets] != secretsPresent {
		t.Fatal("missing creation-time secrets annotation")
	}
	for _, m := range spec.Mounts {
		if strings.HasPrefix(m.Destination, "/run/sops") {
			t.Errorf("marker mount not removed: %+v", m)
		}
	}
	last := spec.Mounts[len(spec.Mounts)-1]
	if last.Destination != "/run/secrets" || last.Type != "tmpfs" || !slices.Contains(last.Options, "noexec") {
		t.Errorf("unexpected tmpfs mount %+v", last)
	}
	if len(spec.Hooks.CreateRuntime) != 2 || spec.Hooks.CreateRuntime[0].Path != "/usr/bin/other" {
		t.Fatalf("existing hook not preserved: %+v", spec.Hooks.CreateRuntime)
	}
	if len(spec.Hooks.CreateContainer) != 1 {
		t.Fatalf("missing createContainer hook")
	}
	p, err := injection.ParseParams(spec.Hooks.CreateRuntime[1].Args[3:])
	if err != nil {
		t.Fatal(err)
	}
	want := injection.Params{Source: "/srv/app/secrets.sops.yaml", Rootfs: "/run/bundle/rootfs", UID: 1000, GID: 1001}
	if p.Source != want.Source || p.Rootfs != want.Rootfs || p.UID != want.UID || p.GID != want.GID || p.Keys != nil {
		t.Errorf("got %+v, want %+v", p, want)
	}

	var raw map[string]json.RawMessage
	_ = json.Unmarshal(out, &raw)
	if string(raw["futureField"]) != `{"kept":true}` || string(raw["unknownSlice"]) != `[1,2]` {
		t.Errorf("unknown fields not preserved: %s %s", raw["futureField"], raw["unknownSlice"])
	}

	again, changed, err := Rewrite(out, "/run/bundle", self, fakeStat)
	if err != nil || changed || string(again) != string(out) {
		t.Errorf("rewrite not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestRewriteAnnotations(t *testing.T) {
	cfg := baseConfig(sopsMount("/run/sops/x"))
	cfg["root"] = map[string]any{"path": "/var/lib/docker/rootfs"}
	cfg["annotations"] = map[string]string{
		annotationKeys:  "A, B_2",
		annotationOwner: "65532:65533",
		"other":         "x",
	}
	out, _, err := rewrite(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var spec specs.Spec
	_ = json.Unmarshal(out, &spec)
	p, err := injection.ParseParams(spec.Hooks.CreateContainer[0].Args[3:])
	if err != nil {
		t.Fatal(err)
	}
	if p.Rootfs != "/var/lib/docker/rootfs" || p.UID != 65532 || p.GID != 65533 || !slices.Equal(p.Keys, []string{"A", "B_2"}) {
		t.Errorf("got %+v", p)
	}
}

func TestRewriteErrors(t *testing.T) {
	tests := map[string]func(map[string]any){
		"two documents": func(c map[string]any) {
			c["mounts"] = append(c["mounts"].([]any), sopsMount("/run/sops/b"))
		},
		"secrets mount": func(c map[string]any) {
			c["mounts"] = append(c["mounts"].([]any), map[string]any{"destination": "/run/secrets/x", "type": "bind", "source": "/x"})
		},
		"secrets mount itself": func(c map[string]any) {
			c["mounts"] = append(c["mounts"].([]any), map[string]any{"destination": "/run/secrets/", "type": "tmpfs", "source": "tmpfs"})
		},
		"directory source": func(c map[string]any) {
			c["mounts"] = []any{map[string]any{"destination": "/run/sops/x", "type": "bind", "source": "/srv/dir"}}
		},
		"nested sops mount": func(c map[string]any) {
			c["mounts"] = append(c["mounts"].([]any), map[string]any{"destination": "/run/sops/a/b", "type": "bind", "source": "/x"})
		},
		"bad keys":       func(c map[string]any) { c["annotations"] = map[string]string{annotationKeys: "A,1B"} },
		"duplicate keys": func(c map[string]any) { c["annotations"] = map[string]string{annotationKeys: "A,A"} },
		"empty keys":     func(c map[string]any) { c["annotations"] = map[string]string{annotationKeys: ""} },
		"bad owner":      func(c map[string]any) { c["annotations"] = map[string]string{annotationOwner: "root"} },
		"negative owner": func(c map[string]any) { c["annotations"] = map[string]string{annotationOwner: "-1:0"} },
		"unknown":        func(c map[string]any) { c["annotations"] = map[string]string{annotationPrefix + "mode": "0400"} },
		"user namespace": func(c map[string]any) {
			c["linux"] = map[string]any{"namespaces": []any{map[string]any{"type": "user"}}}
		},
		"no root": func(c map[string]any) { delete(c, "root") },
		"relative source": func(c map[string]any) {
			c["mounts"] = []any{map[string]any{"destination": "/run/sops/x", "type": "bind", "source": "x"}}
		},
		"already prepared": func(c map[string]any) {
			c["hooks"] = map[string]any{"createContainer": []any{map[string]any{"path": self, "args": []string{"x", "hook", injection.CreateRuntimeHook}}}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := baseConfig(sopsMount("/run/sops/secrets.yaml"))
			mutate(cfg)
			if _, _, err := rewrite(t, cfg); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestPrepareBundle(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.yaml")
	if err := os.WriteFile(doc, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := sopsMount("/run/sops/doc.yaml")
	m["source"] = doc
	data, _ := json.Marshal(baseConfig(m))
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := PrepareBundle(dir, self); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfgPath)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v %v", info, err)
	}
	out, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(out), `"/run/secrets"`) {
		t.Error("config not rewritten")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("unexpected files left: %v", entries)
	}
}

func TestHasSecrets(t *testing.T) {
	plain, _ := json.Marshal(baseConfig())
	if has, err := HasSecrets(plain); err != nil || has {
		t.Errorf("plain config: %v %v", has, err)
	}
	marked, _ := json.Marshal(baseConfig(sopsMount("/run/sops/x")))
	if has, _ := HasSecrets(marked); !has {
		t.Error("marker not detected")
	}
	prepared, _, err := Rewrite(marked, "/run/bundle", self, fakeStat)
	if err != nil {
		t.Fatal(err)
	}
	if has, _ := HasSecrets(prepared); !has {
		t.Error("prepared config not detected")
	}
}

func TestClassifyPreviouslyPreparedBundle(t *testing.T) {
	out, _, err := rewrite(t, baseConfig(sopsMount("/run/sops/x")))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	delete(cfg, "hooks")
	for _, annotations := range []map[string]string{nil, {annotationSecrets: secretsAbsent}} {
		cfg["annotations"] = annotations
		out, changed, err := rewrite(t, cfg)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		var spec specs.Spec
		if err := json.Unmarshal(out, &spec); err != nil || spec.Annotations[annotationSecrets] != secretsPresent {
			t.Fatalf("legacy secret mount classified incorrectly: %v", err)
		}
	}
}

func TestRefuseRestore(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(baseConfig(sopsMount("/run/sops/x")))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareBundle(dir, self, true); err == nil {
		t.Error("restore with secrets allowed")
	}
}
