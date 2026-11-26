package sops

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
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
