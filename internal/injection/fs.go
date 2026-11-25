package injection

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	secretsRel = "run/secrets"
	secretMode = 0o400
	// One page per file plus 1 MiB of values fits the 4 MiB tmpfs.
	MaxSecrets  = 512
	inRootFlags = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS
)

// Host-controlled path, so symlinks are allowed.
func openRootfs(dirfd int, rootfs string) (int, error) {
	rel := strings.TrimPrefix(filepath.Clean(rootfs), "/")
	if rel == "" {
		rel = "."
	}
	fd, err := unix.Openat2(dirfd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("cannot open rootfs %s: %w", rootfs, err)
	}
	return fd, nil
}

func openSecretsDir(rootfd int, flags int) (int, error) {
	fd, err := unix.Openat2(rootfd, secretsRel, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: inRootFlags,
	})
	if err != nil {
		return -1, fmt.Errorf("cannot open %s: %w", SecretsDir, err)
	}
	if err := checkTmpfsRoot(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func checkTmpfsRoot(fd int) error {
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return fmt.Errorf("cannot statfs %s: %w", SecretsDir, err)
	}
	if sfs.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("%s is not a tmpfs", SecretsDir)
	}
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx); err != nil {
		return fmt.Errorf("cannot statx %s: %w", SecretsDir, err)
	}
	if stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return errors.New("kernel does not report mount roots")
	}
	if stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return fmt.Errorf("%s is not a mount point", SecretsDir)
	}
	return nil
}

func checkEmpty(fd int) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), SecretsDir)
	defer f.Close()
	// Shares fd's directory offset.
	if _, err := unix.Seek(dup, 0, io.SeekStart); err != nil {
		return fmt.Errorf("cannot read %s: %w", SecretsDir, err)
	}
	names, err := f.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("cannot read %s: %w", SecretsDir, err)
	}
	if len(names) > 0 {
		return fmt.Errorf("%s is not empty", SecretsDir)
	}
	return nil
}

func writeSecrets(dirfd int, secrets map[string][]byte, uid, gid uint32) error {
	if len(secrets) > MaxSecrets {
		return fmt.Errorf("%d secrets selected, more than the limit of %d", len(secrets), MaxSecrets)
	}
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		if !ValidName(name) {
			return fmt.Errorf("key %q cannot be a secret file name (must match [A-Za-z_][A-Za-z0-9_]*); select other keys with com.greboid.secrets.keys", name)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := writeSecret(dirfd, name, secrets[name], uid, gid); err != nil {
			return fmt.Errorf("cannot write secret %s: %w", name, err)
		}
	}
	return nil
}

func writeSecret(dirfd int, name string, value []byte, uid, gid uint32) error {
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, secretMode)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, err := f.Write(value); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	return unix.Fchmod(fd, secretMode)
}

func sealMount(fd int) error {
	err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &unix.MountAttr{
		Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC,
	})
	if err != nil {
		return fmt.Errorf("cannot make %s read-only: %w", SecretsDir, err)
	}
	return nil
}
