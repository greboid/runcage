package injection

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"g5d.dev/runcage/identity"
)

func TestParamsRoundTrip(t *testing.T) {
	p := Params{Source: "/a/b", Rootfs: "/r", UID: 1, GID: 2, Keys: []string{"X", "Y"}}
	args := p.Args(CreateRuntimeHook)
	got, err := ParseParams(args[3:])
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != p.Source || got.Rootfs != p.Rootfs || got.UID != 1 || got.GID != 2 || !slices.Equal(got.Keys, p.Keys) {
		t.Errorf("got %+v", got)
	}
	if _, err := ParseParams(append(args[3:], "extra")); err == nil {
		t.Error("expected error for extra argument")
	}
	if _, err := ParseParams([]string{"--source=rel", "--rootfs=/r", "--owner=0:0"}); err == nil {
		t.Error("expected error for relative source")
	}
}

func TestSelect(t *testing.T) {
	values := map[string][]byte{"A": []byte("1"), "B": []byte("2")}
	if got, _ := Select(values, nil); len(got) != 2 {
		t.Error("empty selection should return all")
	}
	got, err := Select(values, []string{"B"})
	if err != nil || len(got) != 1 || string(got["B"]) != "2" {
		t.Errorf("got %v %v", got, err)
	}
	if _, err := Select(values, []string{"C"}); err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestWriteSecrets(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := checkEmpty(fd); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	values := map[string][]byte{"A": []byte("x\n"), "EMPTY": {}}
	if err := writeSecrets(fd, values, uid, gid); err != nil {
		t.Fatal(err)
	}
	for name, want := range values {
		path := filepath.Join(dir, name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Errorf("%s: got %q %v", name, got, err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o400 {
			t.Errorf("%s: mode %v", name, info.Mode())
		}
	}
	if err := checkEmpty(fd); err == nil {
		t.Error("expected non-empty error")
	}
	if err := writeSecrets(fd, map[string][]byte{"A": nil}, uid, gid); err == nil {
		t.Error("expected error overwriting existing file")
	}
	many := map[string][]byte{}
	for i := range MaxSecrets + 1 {
		many[fmt.Sprintf("K%d", i)] = nil
	}
	if err := writeSecrets(fd, many, uid, gid); err == nil {
		t.Error("expected error for too many secrets")
	}
	if err := writeSecrets(fd, map[string][]byte{"../x": nil}, uid, gid); err == nil {
		t.Error("expected error for invalid name")
	}
}

func TestOpenSecretsDirRejects(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "real", "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "run")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := openSecretsDir(fd, unix.O_PATH); !errors.Is(err, unix.ELOOP) {
		t.Errorf("symlinked /run: got %v, want ELOOP", err)
	}

	if err := os.Remove(filepath.Join(root, "run")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "run", "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = openSecretsDir(fd, unix.O_PATH)
	if err == nil || !(strings.Contains(err.Error(), "not a tmpfs") || strings.Contains(err.Error(), "not a mount point")) {
		t.Errorf("plain directory: got %v", err)
	}
}

func TestOpenRootfs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	rfd, err := openRootfs(fd, "/link/rootfs")
	if err != nil {
		t.Fatalf("host symlinks in rootfs path should resolve: %v", err)
	}
	unix.Close(rfd)
	if _, err := openRootfs(fd, "/missing"); err == nil {
		t.Error("expected error")
	}
}

func TestLoadSOPS(t *testing.T) {
	testdata := filepath.Join("..", "..", "sops", "testdata")
	t.Cleanup(func() { IdentitySource = identity.DefaultSource })
	key, err := os.ReadFile(filepath.Join(testdata, "identity-test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "age-key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	IdentitySource = func() identity.Source { return identity.Source{Path: keyPath} }
	values, err := loadSOPS(filepath.Join(testdata, "valid.age.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(values["db_password"]) != "hunter2 " || string(values["multiline"]) != "line one\nline two\n" {
		t.Errorf("values not preserved: %q", values)
	}
	if _, err := loadSOPS(filepath.Join(testdata, "missing.yaml")); err == nil {
		t.Error("missing document accepted")
	}
	if _, err := loadSOPS(filepath.Join(testdata, "wrong-key.age.yaml")); err == nil {
		t.Error("undecryptable document accepted")
	}
	IdentitySource = func() identity.Source { return identity.Source{Path: filepath.Join(testdata, "missing")} }
	if _, err := loadSOPS(filepath.Join(testdata, "valid.age.yaml")); err == nil {
		t.Error("missing identity accepted")
	}
}
