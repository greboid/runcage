package identity

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "sops", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	ids, err := Parse(testdata(t, "identity-test.txt"))
	if err != nil || len(ids) == 0 {
		t.Fatalf("valid identity: %v", err)
	}
	for _, name := range []string{"identity-plugin.txt", "identity-ssh.txt", "identity-empty.txt"} {
		raw := testdata(t, name)
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			if l := strings.TrimSpace(line); len(l) > 8 && !strings.HasPrefix(l, "#") && strings.Contains(err.Error(), l) {
				t.Errorf("%s: error leaks line content: %v", name, err)
			}
		}
	}
	if _, err := Parse([]byte("AGE-SECRET-KEY-1INVALID\n")); err == nil || strings.Contains(err.Error(), "INVALID") {
		t.Errorf("invalid key: %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, testdata(t, "identity-test.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), Source{Path: path}); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), Source{Path: link}); err == nil {
		t.Error("symlinked identity accepted")
	}
	if _, err := Load(context.Background(), Source{Path: path + ".missing"}); err == nil {
		t.Error("missing identity accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), Source{Path: path}); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("group-readable identity: %v", err)
	}
}

func fakeServer(t *testing.T, reply func(method string, params json.RawMessage) string) *CredsClient {
	t.Helper()
	dir, err := os.MkdirTemp("", "varlink")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				msg, err := bufio.NewReader(conn).ReadBytes(0)
				if err != nil {
					return
				}
				var call struct {
					Method     string          `json:"method"`
					Parameters json.RawMessage `json:"parameters"`
				}
				if json.Unmarshal(msg[:len(msg)-1], &call) != nil {
					return
				}
				_, _ = conn.Write([]byte(reply(call.Method, call.Parameters) + "\x00"))
			}()
		}
	}()
	return NewCredsClientAt("unix:" + path)
}

func TestCredsDecrypt(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	client := fakeServer(t, func(method string, params json.RawMessage) string {
		var p struct{ Name, Blob string }
		_ = json.Unmarshal(params, &p)
		if method != CredsInterface+".Decrypt" || p.Name != "age-key" || p.Blob != blob {
			t.Errorf("unexpected call %s %+v", method, p)
		}
		return fmt.Sprintf(`{"parameters":{"data":%q}}`, base64.StdEncoding.EncodeToString([]byte("plain")))
	})
	got, err := client.Decrypt(context.Background(), "age-key", blob)
	if err != nil || string(got) != "plain" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := client.Decrypt(context.Background(), "age-key", "not base64!"); err == nil {
		t.Error("invalid blob accepted")
	}
}

func TestCredsErrors(t *testing.T) {
	tests := map[string]string{
		`{"error":"io.systemd.Credentials.NameMismatch","parameters":null}`:                                     "name does not match",
		`{"error":"io.systemd.Credentials.UnexpectedPCRState","parameters":null}`:                               "PCR",
		`{"error":"org.varlink.service.InterfaceNotFound","parameters":{"interface":"io.systemd.Credentials"}}`: "systemd >= 258",
	}
	for reply, want := range tests {
		client := fakeServer(t, func(string, json.RawMessage) string { return reply })
		_, err := client.Decrypt(context.Background(), "n", "eA==")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", reply, err, want)
		}
	}
}

func TestRecipients(t *testing.T) {
	ids, err := Parse(testdata(t, "identity-test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r := Recipients(ids)
	if len(r) != 1 || !strings.HasPrefix(r[0], "age1") {
		t.Fatalf("got %v", r)
	}
}
