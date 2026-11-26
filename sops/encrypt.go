package sops

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"filippo.io/age"
	"go.yaml.in/yaml/v4"
)

// Returned by Rekey without identities when recipients would change.
var ErrIdentityRequired = errors.New("an age identity is required to change recipients")

// Comments are dropped.
func Encrypt(plaintext []byte, recipients []*age.X25519Recipient, limits Limits) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no age recipients given")
	}
	root, err := parseYAML(plaintext)
	if err != nil {
		return nil, fmt.Errorf("plaintext rejected: %w", err)
	}
	entries, _, err := flatEntries(root.Content[0], false, "")
	if err != nil {
		return nil, fmt.Errorf("plaintext rejected: %w", err)
	}
	secrets := make([]Secret, len(entries))
	values := make([]string, len(entries))
	body := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	d := &document{
		root:   &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{body}},
		body:   body,
		sopsAt: -1,
		meta:   metadata{suffix: defaultUnencryptedSuffix},
	}
	for i, e := range entries {
		if strings.HasSuffix(e.name, defaultUnencryptedSuffix) {
			return nil, fmt.Errorf("plaintext rejected: secret %q ends with %q, which SOPS leaves unencrypted", e.name, defaultUnencryptedSuffix)
		}
		secrets[i] = Secret{Name: e.name, Value: e.value.Value}
		values[i] = e.value.Value
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e.name}
		value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}
		body.Content = append(body.Content, key, value)
		d.entries = append(d.entries, entry{name: e.name, value: value})
	}
	if err := ValidateFlat(secrets, limits); err != nil {
		return nil, fmt.Errorf("plaintext rejected: %w", err)
	}
	dataKey, err := newDataKey()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(recipients))
	for i, r := range recipients {
		names[i] = r.String()
	}
	if d.meta.age, err = wrapDataKeyFor(dataKey, names); err != nil {
		return nil, err
	}
	if err := d.seal(dataKey, values); err != nil {
		return nil, err
	}
	return d.emit()
}

func Recipients(encrypted []byte) ([]string, error) {
	d, err := parseEncrypted(encrypted)
	if err != nil {
		return nil, err
	}
	return d.meta.recipients(), nil
}

// Removing rotates the data key. An unchanged document is returned as is
// with false, without needing identities.
func Rekey(encrypted []byte, identities []age.Identity, add, remove []string, limits Limits) ([]byte, bool, error) {
	for _, r := range slices.Concat(add, remove) {
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return nil, false, fmt.Errorf("invalid age recipient %q", r)
		}
	}
	d, err := parseEncrypted(encrypted)
	if err != nil {
		return nil, false, err
	}
	have := d.meta.recipients()
	var missing []string
	for _, r := range add {
		if !slices.Contains(have, r) && !slices.Contains(missing, r) && !slices.Contains(remove, r) {
			missing = append(missing, r)
		}
	}
	drop := slices.ContainsFunc(have, func(r string) bool { return slices.Contains(remove, r) })
	if len(missing) == 0 && !drop {
		return encrypted, false, nil
	}
	if len(identities) == 0 {
		return nil, false, ErrIdentityRequired
	}
	dataKey, err := d.unwrap(identities)
	if err != nil {
		return nil, false, errors.New("data key recovery failed: the age identity cannot decrypt this document")
	}
	values, err := d.open(dataKey)
	if err != nil {
		return nil, false, err
	}
	if err := ValidateFlat(d.secrets(values), limits); err != nil {
		return nil, false, fmt.Errorf("decrypted document rejected: %w", err)
	}

	if !drop {
		stanzas, err := wrapDataKeyFor(dataKey, missing)
		if err != nil {
			return nil, false, err
		}
		d.meta.age = append(d.meta.age, stanzas...)
	} else {
		keep := slices.DeleteFunc(slices.Concat(have, missing), func(r string) bool { return slices.Contains(remove, r) })
		if len(keep) == 0 {
			return nil, false, errors.New("removing every recipient would leave the document undecryptable")
		}
		newKey, err := newDataKey()
		if err != nil {
			return nil, false, err
		}
		stanzas, err := wrapDataKeyFor(newKey, keep)
		if err != nil {
			return nil, false, err
		}
		if err := reencryptComments(d.root, dataKey, newKey); err != nil {
			return nil, false, err
		}
		if err := d.seal(newKey, values); err != nil {
			return nil, false, err
		}
		d.meta.age = stanzas
	}
	out, err := d.emit()
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}
