// Unsupported metadata is rejected: it could change what is encrypted or MACed.

package sops

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v4"
)

const (
	sopsMetadataKey          = "sops"
	defaultUnencryptedSuffix = "_unencrypted"
	nonceSize                = 32
	tagSize                  = 16
	dataKeySize              = 32
)

var encPattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/=]*),iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:([a-z]+)\]$`)

// SOPS writes these empty when unused; only empty is accepted.
var emptyKeyFields = map[string]bool{"kms": true, "gcp_kms": true, "azure_kv": true, "hc_vault": true, "pgp": true, "hckms": true}
var emptyOptionFields = map[string]bool{
	"encrypted_suffix": true, "unencrypted_regex": true, "encrypted_regex": true,
	"unencrypted_comment_regex": true, "encrypted_comment_regex": true,
	"key_groups": true, "shamir_threshold": true, "mac_only_encrypted": true,
}

var (
	errDecrypt = errors.New("decryption failed: an encrypted value could not be decrypted with the recovered data key")
	errMAC     = errors.New("integrity check failed: MAC mismatch, the document was modified after encryption or is corrupted")
)

type encValue struct {
	data, iv, tag []byte
	typ           string
}

func parseEnc(s string) (*encValue, bool) {
	m := encPattern.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	var v encValue
	for i, dst := range []*[]byte{&v.data, &v.iv, &v.tag} {
		b, err := base64.StdEncoding.DecodeString(m[i+1])
		if err != nil {
			return nil, false
		}
		*dst = b
	}
	if len(v.iv) != nonceSize || len(v.tag) != tagSize {
		return nil, false
	}
	v.typ = m[4]
	return &v, true
}

func (v *encValue) open(key []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, v.iv, append(bytes.Clone(v.data), v.tag...), []byte(aad))
}

// SHA-512 over all values in document order.
func macOf(values []string) string {
	h := sha512.New()
	for _, v := range values {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("%X", h.Sum(nil))
}

type ageStanza struct {
	recipient, enc string
}

type metadata struct {
	age          []ageStanza
	lastModified string
	mac          string
	// Empty means the default.
	suffix string
}

func (m *metadata) unencryptedSuffix() string {
	if m.suffix == "" {
		return defaultUnencryptedSuffix
	}
	return m.suffix
}

// SOPS authenticates lastmodified re-formatted.
func (m *metadata) macAAD() string {
	t, _ := time.Parse(time.RFC3339, m.lastModified)
	return t.Format(time.RFC3339)
}

func stringScalar(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", false
	}
	return n.Value, true
}

func isEmptyField(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) == 0
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return true
		case "!!str":
			return n.Value == ""
		case "!!int":
			return n.Value == "0"
		case "!!bool":
			return n.Value == "false"
		}
	}
	return false
}

func parseMetadata(n *yaml.Node) (metadata, error) {
	var m metadata
	if n.Kind != yaml.MappingNode {
		return m, fmt.Errorf("SOPS metadata is not a mapping")
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		name, ok := stringScalar(n.Content[i])
		if !ok {
			return m, fmt.Errorf("SOPS metadata has a non-string key")
		}
		if seen[name] {
			return m, fmt.Errorf("SOPS metadata field %q appears more than once", name)
		}
		seen[name] = true
		v := n.Content[i+1]
		switch {
		case name == "age":
			stanzas, err := parseAgeStanzas(v)
			if err != nil {
				return m, err
			}
			m.age = stanzas
		case name == "lastmodified":
			s, ok := stringScalar(v)
			if !ok {
				return m, fmt.Errorf("SOPS metadata lastmodified is not a string")
			}
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				return m, fmt.Errorf("SOPS metadata lastmodified is not an RFC 3339 timestamp")
			}
			m.lastModified = s
		case name == "mac":
			if m.mac, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata mac is not a string")
			}
		case name == "unencrypted_suffix":
			if m.suffix, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata unencrypted_suffix is not a string")
			}
		case name == "version":
			if _, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata version is not a string")
			}
		case emptyKeyFields[name]:
			if !isEmptyField(v) {
				return m, fmt.Errorf("document uses non-age master keys (%s); only age recipients are supported", name)
			}
		case emptyOptionFields[name]:
			if !isEmptyField(v) {
				return m, fmt.Errorf("unsupported SOPS option %q", name)
			}
		default:
			return m, fmt.Errorf("unsupported SOPS metadata field %q", name)
		}
	}
	switch {
	case len(m.age) == 0:
		return m, fmt.Errorf("document has no age recipients")
	case m.lastModified == "":
		return m, fmt.Errorf("SOPS metadata has no lastmodified timestamp")
	case m.mac == "":
		return m, fmt.Errorf("SOPS metadata has no MAC")
	}
	return m, nil
}

func parseAgeStanzas(n *yaml.Node) ([]ageStanza, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("SOPS metadata age is not a list")
	}
	var out []ageStanza
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("SOPS metadata age entry is not a mapping")
		}
		var s ageStanza
		for i := 0; i+1 < len(item.Content); i += 2 {
			k, ok1 := stringScalar(item.Content[i])
			v, ok2 := stringScalar(item.Content[i+1])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("SOPS metadata age entry has a non-string field")
			}
			switch {
			case k == "recipient" && s.recipient == "":
				s.recipient = v
			case k == "enc" && s.enc == "":
				s.enc = v
			default:
				return nil, fmt.Errorf("SOPS metadata age entry has an unsupported or repeated field %q", k)
			}
		}
		if s.recipient == "" || s.enc == "" {
			return nil, fmt.Errorf("SOPS metadata age entry needs recipient and enc")
		}
		out = append(out, s)
	}
	return out, nil
}

// plain: the name has the unencrypted suffix.
type entry struct {
	name  string
	value *yaml.Node
	plain bool
}

type document struct {
	meta    metadata
	entries []entry
}

func parseYAML(b []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("document contains no secrets")
		}
		return nil, fmt.Errorf("not a valid YAML document")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("document is not a YAML mapping")
	}
	return &root, nil
}

func valueTypeName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "nested mapping"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.AliasNode:
		return "alias"
	}
	switch n.ShortTag() {
	case "!!null":
		return "null"
	case "!!int":
		return "integer"
	case "!!float":
		return "float"
	case "!!bool":
		return "boolean"
	case "!!timestamp":
		return "timestamp"
	}
	return fmt.Sprintf("%q-tagged", n.ShortTag())
}

func encTypeName(t string) string {
	switch t {
	case "int":
		return "integer"
	case "bool":
		return "boolean"
	case "float", "bytes", "comment":
		return t
	case "time":
		return "timestamp"
	}
	return "unknown"
}

func nonString(name, kind string) error {
	return fmt.Errorf("secret %q has a %s value; all values must be YAML strings (quote the value)", name, kind)
}

func flatEntries(body *yaml.Node, suffix string) ([]entry, error) {
	sopsSeen := false
	var entries []entry
	for i := 0; i+1 < len(body.Content); i += 2 {
		k, v := body.Content[i], body.Content[i+1]
		name, ok := stringScalar(k)
		if !ok {
			return nil, fmt.Errorf("secret names must be strings")
		}
		if name == sopsMetadataKey {
			if sopsSeen {
				return nil, fmt.Errorf("document has more than one %q key", sopsMetadataKey)
			}
			sopsSeen = true
			continue
		}
		if !namePattern.MatchString(name) {
			return nil, invalidName(name)
		}
		if _, ok := stringScalar(v); !ok {
			return nil, nonString(name, valueTypeName(v))
		}
		e := entry{name: name, value: v, plain: strings.HasSuffix(name, suffix)}
		if !e.plain && v.Value != "" {
			enc, ok := parseEnc(v.Value)
			if !ok {
				return nil, fmt.Errorf("secret %q is not a SOPS-encrypted value", name)
			}
			if enc.typ != "str" {
				return nil, nonString(name, encTypeName(enc.typ))
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func parseEncrypted(b []byte) (*document, error) {
	root, err := parseYAML(b)
	if err != nil {
		return nil, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes): %w", len(b), err)
	}
	body := root.Content[0]
	var meta metadata
	found := false
	for i := 0; i+1 < len(body.Content); i += 2 {
		if name, ok := stringScalar(body.Content[i]); ok && name == sopsMetadataKey && !found {
			found = true
			if meta, err = parseMetadata(body.Content[i+1]); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes): no %q metadata", len(b), sopsMetadataKey)
	}
	entries, err := flatEntries(body, meta.unencryptedSuffix())
	if err != nil {
		return nil, fmt.Errorf("document rejected: %w", err)
	}
	return &document{meta: meta, entries: entries}, nil
}

func (d *document) unwrap(identities []age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identities")
	}
	for _, s := range d.meta.age {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(s.enc)), identities...)
		if err != nil {
			continue
		}
		key, err := io.ReadAll(io.LimitReader(r, dataKeySize+1))
		if err == nil && len(key) == dataKeySize {
			return key, nil
		}
	}
	return nil, errors.New("no identity matches")
}

// The MAC is verified before any value is returned.
func (d *document) open(dataKey []byte) ([]string, error) {
	values := make([]string, 0, len(d.entries))
	for _, e := range d.entries {
		if e.plain || e.value.Value == "" {
			values = append(values, e.value.Value)
			continue
		}
		enc, _ := parseEnc(e.value.Value)
		pt, err := enc.open(dataKey, e.name+":")
		if err != nil {
			return nil, errDecrypt
		}
		values = append(values, string(pt))
	}
	stored, ok := parseEnc(d.meta.mac)
	if !ok || stored.typ != "str" {
		return nil, errMAC
	}
	mac, err := stored.open(dataKey, d.meta.macAAD())
	if err != nil || subtle.ConstantTimeCompare(mac, []byte(macOf(values))) != 1 {
		return nil, errMAC
	}
	return values, nil
}

func (d *document) secrets(values []string) []Secret {
	out := make([]Secret, len(d.entries))
	for i, e := range d.entries {
		out[i] = Secret{Name: e.name, Value: values[i]}
	}
	return out
}
