package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"g5d.dev/runcage/internal/sops"
)

const (
	// From ImportCredential= on docker.service.
	RuntimePath    = "/run/credentials/docker.service/age-key"
	CredentialPath = "/etc/credstore.encrypted/age-key"
	CredentialName = "age-key"
	FilePath       = "/etc/credstore/age-key"

	maxIdentitySize = 1 << 20
)

type Source struct {
	Credential bool
	Path       string
	Name       string
}

func DefaultSource() Source {
	if _, err := os.Lstat(RuntimePath); err == nil {
		return Source{Path: RuntimePath}
	}
	if _, err := os.Lstat(CredentialPath); err == nil {
		return Source{Credential: true, Path: CredentialPath, Name: CredentialName}
	}
	return Source{Path: FilePath}
}

func Load(ctx context.Context, src Source) ([]age.Identity, error) {
	if src.Credential {
		raw, err := sops.ReadBounded(src.Path, maxIdentitySize, true)
		if err != nil {
			return nil, fmt.Errorf("cannot read age identity: %s", readMessage(src.Path, err))
		}
		client, err := NewCredsClient()
		if err != nil {
			return nil, err
		}
		if raw, err = client.Decrypt(ctx, src.Name, strings.TrimSpace(string(raw))); err != nil {
			return nil, fmt.Errorf("cannot decrypt age identity %s: %w", src.Path, err)
		}
		return Parse(raw)
	}
	raw, err := readPrivate(src.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot read age identity: %s", readMessage(src.Path, err))
	}
	return Parse(raw)
}

// Plugin identities would exec an external binary.
func Parse(raw []byte) ([]age.Identity, error) {
	var kept strings.Builder
	lineNo := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		lineNo++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "AGE-PLUGIN-"):
			return nil, fmt.Errorf("age identity line %d: plugin identities are not supported", lineNo)
		case strings.HasPrefix(trimmed, "-----BEGIN") && strings.HasSuffix(trimmed, "PRIVATE KEY-----"):
			return nil, fmt.Errorf("age identity line %d: SSH private keys are not supported", lineNo)
		case strings.HasPrefix(trimmed, "ssh-ed25519 "), strings.HasPrefix(trimmed, "ssh-rsa "),
			strings.HasPrefix(trimmed, "ecdsa-sha2-"):
			return nil, fmt.Errorf("age identity line %d: SSH public keys are not supported", lineNo)
		case !strings.HasPrefix(upper, "AGE-SECRET-KEY-"):
			return nil, fmt.Errorf("age identity line %d: unsupported line (only AGE-SECRET-KEY-1... identities are supported)", lineNo)
		}
		kept.WriteString(trimmed)
		kept.WriteByte('\n')
	}
	if kept.Len() == 0 {
		return nil, errors.New("age identity contains no identities")
	}
	ids, err := age.ParseIdentities(strings.NewReader(kept.String()))
	if err != nil {
		// Parse errors can quote key material.
		return nil, errors.New("age identity contains an invalid identity")
	}
	return ids, nil
}

func readPrivate(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("%s: not a regular file", path)
	case int(st.Uid) != os.Geteuid():
		return nil, fmt.Errorf("%s: not owned by uid %d", path, os.Geteuid())
	case st.Mode&0o077 != 0:
		return nil, fmt.Errorf("%s: accessible by group or others (want mode 0600 or 0400)", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIdentitySize+1))
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: path, Err: err}
	}
	if len(data) > maxIdentitySize {
		return nil, fmt.Errorf("%s: exceeds the %d byte limit", path, maxIdentitySize)
	}
	return data, nil
}

func readMessage(path string, err error) string {
	if perr, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Sprintf("%s: %s", path, perr.Err.Error())
	}
	return err.Error()
}
