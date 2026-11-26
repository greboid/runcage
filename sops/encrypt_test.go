package sops

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"go.yaml.in/yaml/v4"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEncryptRoundTrip(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	doc, err := Encrypt([]byte("db_password: hunter2\nempty: \"\"\ntoken: \"line1\\nline2\"\n"), []*age.X25519Recipient{a.Recipient(), b.Recipient()}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(doc, []byte("hunter2")) {
		t.Fatal("ciphertext contains plaintext")
	}
	for _, id := range []age.Identity{a, b} {
		secrets, err := Decrypt(doc, []age.Identity{id}, DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		want := []Secret{{"db_password", "hunter2"}, {"empty", ""}, {"token", "line1\nline2"}}
		if !slices.Equal(secrets, want) {
			t.Fatalf("got %v", secrets)
		}
	}
	r, err := Recipients(doc)
	if err != nil || !slices.Equal(r, []string{a.Recipient().String(), b.Recipient().String()}) {
		t.Fatalf("recipients %v %v", r, err)
	}
}

// An empty value leaves the MAC unchanged, so this needs no key to add.
func TestDecryptRejectsUnencrypted(t *testing.T) {
	id := newIdentity(t)
	doc, err := Encrypt([]byte("a: b\n"), []*age.X25519Recipient{id.Recipient()}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	doc = append(doc, "LD_PRELOAD_unencrypted: \"\"\n"...)
	_, err = Decrypt(doc, []age.Identity{id}, DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD_unencrypted") {
		t.Fatalf("unencrypted entry accepted: %v", err)
	}
}

func TestEncryptRejections(t *testing.T) {
	r := []*age.X25519Recipient{newIdentity(t).Recipient()}
	for _, in := range []string{"a: 1\n", "a: {b: c}\n", "sops: x\n", "a_unencrypted: x\n", "", "x.y z: a\n"} {
		if _, err := Encrypt([]byte(in), r, DefaultLimits); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := Encrypt([]byte("a: b\n"), nil, DefaultLimits); err == nil {
		t.Error("no recipients accepted")
	}
}

func TestRekey(t *testing.T) {
	ids := identities(t, "identity-test.txt")
	doc := fixture(t, "valid.age.yaml")
	have, err := Recipients(doc)
	if err != nil {
		t.Fatal(err)
	}
	if out, changed, err := Rekey(doc, nil, have, nil, DefaultLimits); err != nil || changed || !bytes.Equal(out, doc) {
		t.Fatalf("unchanged rekey: %v %v", changed, err)
	}
	other := newIdentity(t)
	r := other.Recipient().String()
	if _, _, err := Rekey(doc, nil, []string{r}, nil, DefaultLimits); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("got %v", err)
	}
	added, changed, err := Rekey(doc, ids, []string{r}, nil, DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("add: %v %v", changed, err)
	}
	for _, id := range [][]age.Identity{ids, {other}} {
		if s, err := Decrypt(added, id, DefaultLimits); err != nil || len(s) != len(validOrder) {
			t.Fatalf("decrypt after add: %v", err)
		}
	}
	removed, changed, err := Rekey(added, []age.Identity{other}, nil, have, DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("remove: %v %v", changed, err)
	}
	if _, err := Decrypt(removed, ids, DefaultLimits); err == nil {
		t.Fatal("removed key still decrypts")
	}
	if s, err := Decrypt(removed, []age.Identity{other}, DefaultLimits); err != nil || s[0].Value != validValues[validOrder[0]] {
		t.Fatalf("decrypt after remove: %v", err)
	}
	if _, _, err := Rekey(removed, []age.Identity{other}, nil, []string{r}, DefaultLimits); err == nil || !strings.Contains(err.Error(), "every recipient") {
		t.Fatalf("removing all: %v", err)
	}
	if _, _, err := Rekey(doc, ids, []string{"age1bad"}, nil, DefaultLimits); err == nil {
		t.Fatal("invalid recipient accepted")
	}
}

func TestRekeyRejectsUnencrypted(t *testing.T) {
	doc := strings.Replace(string(fixture(t, "valid.age.yaml")), "sops:", "x_unencrypted: \"\"\nsops:", 1)
	r := newIdentity(t).Recipient().String()
	if _, _, err := Rekey([]byte(doc), identities(t, "identity-test.txt"), []string{r}, nil, DefaultLimits); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Fatalf("got %v", err)
	}
}

func TestRekeyKeepsVersion(t *testing.T) {
	a := newIdentity(t)
	doc, err := Encrypt([]byte("a: b\n"), []*age.X25519Recipient{a.Recipient()}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	doc = []byte(strings.Replace(string(doc), "    version: "+formatVersion+"\n", "", 1))
	out, _, err := Rekey(doc, []age.Identity{a}, []string{newIdentity(t).Recipient().String()}, nil, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "version") {
		t.Fatalf("version added:\n%s", out)
	}
}

// A label that does not match its stanza is rewrapped to the label.
func TestRekeyRewrapsStanzas(t *testing.T) {
	a, b, c := newIdentity(t), newIdentity(t), newIdentity(t)
	doc, err := Encrypt([]byte("a: b\n"), []*age.X25519Recipient{a.Recipient()}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	doc = []byte(strings.Replace(string(doc), a.Recipient().String(), b.Recipient().String(), 1))
	out, changed, err := Rekey(doc, []age.Identity{a}, []string{c.Recipient().String()}, nil, DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if _, err := Decrypt(out, []age.Identity{a}, DefaultLimits); err == nil {
		t.Error("unlabelled key still decrypts")
	}
	for _, id := range []age.Identity{b, c} {
		if _, err := Decrypt(out, []age.Identity{id}, DefaultLimits); err != nil {
			t.Error(err)
		}
	}
}

func TestRekeyRotatesComments(t *testing.T) {
	ids := identities(t, "identity-test.txt")
	have, err := Recipients(fixture(t, "valid.age.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(fixture(t, "valid.age.yaml")), "sops:", "# plain\n#ENC[AES256_GCM,data:AAAA,iv:"+strings.Repeat("A", 43)+"=,tag:"+strings.Repeat("A", 22)+"==,type:comment]\nsops:", 1)
	other := newIdentity(t)
	out, _, err := Rekey([]byte(doc), ids, []string{other.Recipient().String()}, have, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseEncrypted(out)
	if err != nil {
		t.Fatal(err)
	}
	key, err := d.unwrap([]age.Identity{other})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		for _, c := range []string{n.HeadComment, n.LineComment, n.FootComment} {
			for line := range strings.SplitSeq(c, "\n") {
				if line == "" {
					continue
				}
				enc, ok := parseEnc(strings.TrimPrefix(line, "#"))
				if !ok || enc.typ != "comment" {
					t.Fatalf("comment not encrypted: %q", line)
				}
				pt, err := enc.open(key, commentAAD)
				if err != nil {
					t.Fatalf("comment not under new key: %q", line)
				}
				got = append(got, string(pt))
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(d.root)
	want := []string{" compose-sops test document", " plain", "ENC[AES256_GCM,data:AAAA,iv:" + strings.Repeat("A", 43) + "=,tag:" + strings.Repeat("A", 22) + "==,type:comment]"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}
