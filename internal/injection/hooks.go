package injection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"g5d.dev/runcage/internal/identity"
	"g5d.dev/runcage/internal/sops"
)

const maxStateSize = 1 << 20

type Loader func(source string) (map[string][]byte, error)

var LoadDocument Loader = loadSOPS

var IdentitySource = identity.DefaultSource

// Below the createRuntime hook timeout.
const identityTimeout = 45 * time.Second

func loadSOPS(source string) (map[string][]byte, error) {
	encrypted, err := sops.ReadDocument(source)
	if err != nil {
		return nil, fmt.Errorf("cannot read document: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityTimeout)
	defer cancel()
	ids, err := identity.Load(ctx, IdentitySource())
	if err != nil {
		return nil, err
	}
	secrets, err := sops.Decrypt(encrypted, ids, sops.DefaultLimits)
	if err != nil {
		return nil, fmt.Errorf("document %s: %w", source, err)
	}
	values := make(map[string][]byte, len(secrets))
	for _, s := range secrets {
		values[s.Name] = []byte(s.Value)
	}
	return values, nil
}

func Main(args []string, stdin io.Reader, stderr io.Writer) int {
	if err := run(args, stdin); err != nil {
		fmt.Fprintf(stderr, "secret-runc: %v\n", err)
		return 1
	}
	return 0
}

func run(args []string, stdin io.Reader) error {
	if len(args) == 0 {
		return errors.New("missing hook name")
	}
	p, err := ParseParams(args[1:])
	if err != nil {
		return fmt.Errorf("invalid hook arguments: %w", err)
	}
	state, err := readState(stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case CreateRuntimeHook:
		return createRuntime(p, state)
	case CreateContainerHook:
		return createContainer(p)
	default:
		return fmt.Errorf("unknown hook %q", args[0])
	}
}

func readState(r io.Reader) (specs.State, error) {
	var s specs.State
	data, err := io.ReadAll(io.LimitReader(r, maxStateSize+1))
	if err != nil {
		return s, fmt.Errorf("cannot read state: %w", err)
	}
	if len(data) > maxStateSize {
		return s, errors.New("state too large")
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("invalid state: %w", err)
	}
	if s.Pid <= 0 {
		return s, errors.New("state has no pid")
	}
	return s, nil
}

// Host namespaces, before pivot_root: reaches the tmpfs via /proc/<pid>/root.
func createRuntime(p Params, state specs.State) error {
	values, err := LoadDocument(p.Source)
	if err != nil {
		return err
	}
	secrets, err := Select(values, p.Keys)
	if err != nil {
		return err
	}
	nsRoot, err := unix.Open(fmt.Sprintf("/proc/%d/root", state.Pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open container mount namespace: %w", err)
	}
	defer unix.Close(nsRoot)
	rootfd, err := openRootfs(nsRoot, p.Rootfs)
	if err != nil {
		return err
	}
	defer unix.Close(rootfd)
	dirfd, err := openSecretsDir(rootfd, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	if err := checkEmpty(dirfd); err != nil {
		return err
	}
	return writeSecrets(dirfd, secrets, p.UID, p.GID)
}

// Container mount namespace, before pivot_root.
func createContainer(p Params) error {
	nsRoot, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open mount namespace root: %w", err)
	}
	defer unix.Close(nsRoot)
	rootfd, err := openRootfs(nsRoot, p.Rootfs)
	if err != nil {
		return err
	}
	defer unix.Close(rootfd)
	dirfd, err := openSecretsDir(rootfd, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	return sealMount(dirfd)
}
