package sops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

// testdata was encrypted by the sops CLI.

var validValues = map[string]string{
	"db_password":   "hunter2 ",
	"api_key":       "abc123",
	"multiline":     "line one\nline two\n",
	"empty":         "",
	"quoted_number": "0042",
	"unicode":       "pässwörd-ключ-密钥",
}

var validOrder = []string{"db_password", "api_key", "multiline", "empty", "quoted_number", "unicode"}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func identities(t *testing.T, name string) []age.Identity {
	t.Helper()
	ids, err := age.ParseIdentities(strings.NewReader(string(fixture(t, name))))
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestDecryptValid(t *testing.T) {
	secrets, err := Decrypt(fixture(t, "valid.age.yaml"), identities(t, "identity-test.txt"), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != len(validOrder) {
		t.Fatalf("got %d secrets", len(secrets))
	}
	for i, s := range secrets {
		if s.Name != validOrder[i] || s.Value != validValues[s.Name] {
			t.Errorf("%d: got %q=%q", i, s.Name, s.Value)
		}
	}
}

func TestDecryptIgnoresAmbientEnvironment(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", string(fixture(t, "identity-test.txt")))
	if _, err := Decrypt(fixture(t, "valid.age.yaml"), identities(t, "identity-wrong.txt"), DefaultLimits); err == nil {
		t.Fatal("ambient key used")
	}
}

func TestDecryptRejections(t *testing.T) {
	tests := []struct {
		fixture, want string
	}{
		{"wrong-key.age.yaml", "data key recovery failed"},
		{"tampered-mac.age.yaml", "integrity check failed"},
		{"corrupted.age.yaml", "failed"},
		{"nested.age.yaml", "nested"},
		{"nonstring.age.yaml", "must be YAML strings"},
		{"nulbyte.age.yaml", "NUL"},
		{"big.age.yaml", "byte limit"},
	}
	ids := identities(t, "identity-test.txt")
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			_, err := Decrypt(fixture(t, tt.fixture), ids, DefaultLimits)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "nested-secret") {
				t.Fatalf("error leaks plaintext: %v", err)
			}
		})
	}
	if _, err := Decrypt([]byte("not sops"), ids, DefaultLimits); err == nil {
		t.Error("garbage accepted")
	}
}

func TestDecryptRejectsNonAgeMasterKeys(t *testing.T) {
	doc := `v: ENC[AES256_GCM,data:E5cPQzE=,iv:Qg6RXc2oSCVLbfBjRBKgig==,tag:8MILHaYh2ofHKbacD/vecQ==,type:str]
sops:
    pgp:
        - fp: ABCDEF
    lastmodified: "2024-01-01T00:00:00Z"
    mac: x
    version: 3.9.0
`
	_, err := Decrypt([]byte(doc), identities(t, "identity-test.txt"), DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "only age") {
		t.Fatalf("got %v", err)
	}
}

func TestReadBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadBounded(path, 5, true); err != nil || string(b) != "12345" {
		t.Errorf("got %q %v", b, err)
	}
	if _, err := ReadBounded(path, 4, true); err == nil {
		t.Error("oversized file accepted")
	}
	if _, err := ReadBounded(dir, 5, false); err == nil {
		t.Error("directory accepted")
	}
}

func TestReadBoundedFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(path, 5, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("got %v", err)
	}
}
