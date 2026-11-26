package runtime

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedArgsFailClosed(t *testing.T) {
	for _, args := range [][]string{
		{"--future", "value", "checkpoint", "id"},
		{"--future=1", "restore", "id"},
		{"checkpoint"}, {"restore", "--"}, {"checkpoint", "--", "a", "b"},
		{"checkpoint", "--future", "id"}, {"restore", "--image-path"},
		{"restore", "--bundle", "--", "id"}, {"restore", "-b=", "id"},
		{"restore", "-b", "one", "--bundle=two", "id"},
		{"restore", "id", "--bundle=other"},
	} {
		if _, err := ParseArgs(args); err == nil {
			t.Errorf("accepted ambiguous arguments: %q", args)
		}
	}
}

func TestCheckpointState(t *testing.T) {
	for _, tt := range []struct {
		name, id, class string
		allow           bool
	}{
		{"plain", "app", secretsAbsent, true},
		{"secrets", "app", secretsPresent, false},
		{"legacy", "app", "", false},
		{"unknown", "app", "unexpected", false},
		{"wrong ID", "other", secretsAbsent, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			annotations := map[string]string{}
			if tt.class != "" {
				annotations[annotationSecrets] = tt.class
			}
			data, _ := json.Marshal(map[string]any{"id": tt.id, "annotations": annotations})
			if err := checkpointState(data, "app"); (err == nil) != tt.allow {
				t.Errorf("allow=%v, got %v", tt.allow, err)
			}
		})
	}
	if err := checkpointState([]byte(`{`), "app"); err == nil {
		t.Fatal("invalid state accepted")
	}
}

func TestCheckpointUnstampedBundle(t *testing.T) {
	prepared, _, err := Rewrite(mustJSON(t, baseConfig(sopsMount("/run/sops/x"))), "/run/bundle", self, fakeStat)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(prepared, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "annotations")
	for _, tt := range []struct {
		name   string
		config []byte
		allow  bool
	}{
		{"plain", mustJSON(t, baseConfig()), true},
		{"legacy secrets", mustJSON(t, legacy), false},
		{"missing config", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.config != nil {
				if err := os.WriteFile(filepath.Join(dir, "config.json"), tt.config, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			state := mustJSON(t, map[string]any{"id": "app", "bundle": dir})
			if err := checkpointState(state, "app"); (err == nil) != tt.allow {
				t.Errorf("allow=%v, got %v", tt.allow, err)
			}
		})
	}
	if err := checkpointState(mustJSON(t, map[string]any{"id": "app", "bundle": "rel"}), "app"); err == nil {
		t.Error("relative bundle accepted")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCheckpointQueriesSameRuntimeRoot(t *testing.T) {
	runc := filepath.Join(t.TempDir(), "runc")
	script := "#!/bin/sh\n[ \"$#\" = 5 ] && [ \"$1\" = --root ] && [ \"$2\" = /runtime ] && [ \"$3\" = state ] && [ \"$4\" = -- ] && [ \"$5\" = app ] || exit 1\n" +
		`echo '{"id":"app","annotations":{"g5d.dev/runcage/secrets":"absent"}}'` + "\n"
	if err := os.WriteFile(runc, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	inv, err := ParseArgs([]string{"--root", "/runtime", "checkpoint", "app"})
	if err != nil {
		t.Fatal(err)
	}
	if err := refuseCheckpoint(runc, inv); err != nil {
		t.Fatal(err)
	}
	if err := refuseCheckpoint(runc, Invocation{}); err == nil {
		t.Fatal("checkpoint with unresolved ID accepted")
	}
}

func TestRestoreClassification(t *testing.T) {
	for _, tt := range []struct {
		name   string
		fields map[string]any
		refuse bool
	}{
		{"plain", nil, false},
		{"stamp", map[string]any{"annotations": map[string]string{annotationSecrets: secretsPresent}}, true},
		{"unknown stamp", map[string]any{"annotations": map[string]string{annotationSecrets: "future"}}, true},
		{"legacy mount", map[string]any{
			"annotations": map[string]string{annotationSecrets: secretsAbsent},
			"mounts":      []any{map[string]any{"type": "tmpfs", "destination": "/run/secrets/", "options": []string{"noswap", "nodev"}}},
		}, true},
		{"ordinary tmpfs", map[string]any{"mounts": []any{map[string]any{"type": "tmpfs", "destination": "/run/secrets", "options": []string{"nodev"}}}}, false},
		{"relocated hook", map[string]any{"hooks": map[string]any{"createRuntime": []any{map[string]any{"path": "/old/runcage", "args": []string{"runcage", "hook", "create-runtime"}}}}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			maps.Copy(cfg, tt.fields)
			data, _ := json.Marshal(cfg)
			dir := t.TempDir()
			p := filepath.Join(dir, "config.json")
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
			err := prepareBundle(dir, self, true)
			if tt.refuse && !errors.Is(err, errCheckpoint) || !tt.refuse && err != nil {
				t.Fatalf("restore: %v", err)
			}
			out, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != string(data) {
				t.Fatal("restore without secrets changed bundle")
			}
		})
	}
}

func TestRejectAmbiguousBundle(t *testing.T) {
	for _, s := range []string{`null`, `{"Mounts":[]}`, `{"annotations":{},"annotations":{}}`, `{"annotations":{"g5d.dev/runcage/secrets=absent":""}}`} {
		if _, _, err := Rewrite([]byte(s), "/bundle", self, fakeStat); err == nil {
			t.Errorf("accepted ambiguous config: %s", s)
		}
	}
}
