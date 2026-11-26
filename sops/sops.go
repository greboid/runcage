package sops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

type Limits struct {
	MaxValueSize int
	// Sum of all names and values.
	MaxTotalSize int
}

var DefaultLimits = Limits{
	MaxValueSize: 64 << 10,
	MaxTotalSize: 1 << 20,
}

const MaxDocumentSize = 4 << 20

type Secret struct {
	Name  string
	Value string
}

// No leading dot, so "." and ".." cannot match.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// Errors may name keys but never quote values.
func ValidateFlat(secrets []Secret, limits Limits) error {
	if len(secrets) == 0 {
		return fmt.Errorf("document contains no secrets")
	}
	seen := make(map[string]struct{}, len(secrets))
	total := 0
	for _, s := range secrets {
		if !namePattern.MatchString(s.Name) {
			return invalidName(s.Name)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("duplicate secret name %q", s.Name)
		}
		seen[s.Name] = struct{}{}
		if strings.ContainsRune(s.Value, 0) {
			return fmt.Errorf("secret %q contains a NUL byte", s.Name)
		}
		if len(s.Value) > limits.MaxValueSize {
			return fmt.Errorf("secret %q is %d bytes, exceeding the %d byte limit", s.Name, len(s.Value), limits.MaxValueSize)
		}
		total += len(s.Name) + len(s.Value)
		if total > limits.MaxTotalSize {
			return fmt.Errorf("document exceeds the %d byte total size limit", limits.MaxTotalSize)
		}
	}
	return nil
}

func invalidName(name string) error {
	return fmt.Errorf("invalid secret name %q: must match [a-zA-Z0-9_][a-zA-Z0-9._-]* and be at most 128 characters", name)
}

func Decrypt(encrypted []byte, identities []age.Identity, limits Limits) ([]Secret, error) {
	d, err := parseEncrypted(encrypted)
	if err != nil {
		return nil, err
	}
	dataKey, err := d.unwrap(identities)
	if err != nil {
		return nil, errors.New("data key recovery failed: the age identity cannot decrypt this document")
	}
	defer clear(dataKey)
	values, err := d.open(dataKey)
	if err != nil {
		return nil, err
	}
	secrets := d.secrets(values)
	if err := ValidateFlat(secrets, limits); err != nil {
		return nil, fmt.Errorf("decrypted document rejected: %w", err)
	}
	return secrets, nil
}

func ReadDocument(path string) ([]byte, error) {
	return ReadBounded(path, MaxDocumentSize, false)
}

func ReadBounded(path string, limit int64, noFollow bool) ([]byte, error) {
	// O_NONBLOCK: opening a FIFO would otherwise block before the type check.
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if noFollow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", path, limit)
	}
	return data, nil
}
