//go:build linux

package injection

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHookDisablesCoreDumps(t *testing.T) {
	checkAtDocumentLoad(t, func() {
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dumpable != 0 {
			t.Fatalf("PR_GET_DUMPABLE = %d, err = %v", dumpable, err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Cur != 0 || limit.Max != 0 {
			t.Fatalf("RLIMIT_CORE = %+v; want both limits zero", limit)
		}
	})
}

// The hard core limit cannot be restored by an unprivileged test process.
func checkAtDocumentLoad(t *testing.T, check func()) {
	t.Helper()
	const child = "RUNCAGE_HOOK_TEST_CHILD"
	if os.Getenv(child) != t.Name() {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), child+"="+t.Name())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook subprocess: %v\n%s", err, out)
		}
		return
	}
	stop := errors.New("stop before reading any secrets")
	LoadDocument = func(string) (map[string][]byte, error) {
		check()
		return nil, stop
	}
	args := Params{Source: "/unused", Rootfs: "/unused"}.Args(CreateRuntimeHook)
	if err := run(args[2:], strings.NewReader(`{"pid":1}`)); !errors.Is(err, stop) {
		t.Fatalf("expected loader to stop injection, got %v", err)
	}
}
