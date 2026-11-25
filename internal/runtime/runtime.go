package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

const DefaultRunc = "/usr/bin/runc"

// Does not return on success.
func Main(args []string) int {
	inv := ParseArgs(args)
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		report(inv, fmt.Errorf("cannot locate own executable: %w", err))
		return 1
	}
	runc, err := FindRunc(self)
	if err != nil {
		report(inv, err)
		return 1
	}
	switch inv.Command {
	case "create", "run":
		err = PrepareBundle(inv.Bundle, self)
	case "checkpoint":
		err = refuseCheckpoint(runc, inv, self)
	case "restore":
		err = refuseRestore(inv.Bundle, self)
	}
	if err != nil {
		report(inv, err)
		return 1
	}
	err = unix.Exec(runc, append([]string{runc}, args...), os.Environ())
	report(inv, fmt.Errorf("cannot exec %s: %w", runc, err))
	return 1
}

// CRIU would write the tmpfs to disk.
var errCheckpoint = errors.New("checkpoint and restore are not supported for containers with secrets")

func refuseCheckpoint(runc string, inv Invocation, self string) error {
	if inv.ID == "" {
		return nil
	}
	args := append(slices.Clone(inv.Global), "state", inv.ID)
	out, err := exec.Command(runc, args...).Output()
	if err != nil {
		return fmt.Errorf("cannot query container state: %w", err)
	}
	var state struct {
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(out, &state); err != nil || state.Bundle == "" {
		return errors.New("cannot query container state: no bundle")
	}
	return refuseRestore(state.Bundle, self)
}

func refuseRestore(bundle, self string) error {
	if bundle == "" {
		bundle = "."
	}
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return fmt.Errorf("cannot read config: %w", err)
	}
	has, err := HasSecrets(data, self, os.Stat)
	if err != nil {
		return err
	}
	if has {
		return errCheckpoint
	}
	return nil
}

func FindRunc(self string) (string, error) {
	selfInfo, err := os.Stat(self)
	if err != nil {
		return "", fmt.Errorf("cannot stat own executable: %w", err)
	}
	candidates := []string{DefaultRunc}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir != "" && filepath.IsAbs(dir) {
			candidates = append(candidates, filepath.Join(dir, "runc"))
		}
	}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		if os.SameFile(info, selfInfo) {
			continue
		}
		return c, nil
	}
	return "", errors.New("cannot find runc")
}

// containerd reads errors from runc's log, not stderr.
func report(inv Invocation, err error) {
	msg := "runcage: " + err.Error()
	fmt.Fprintln(os.Stderr, msg)
	if inv.Log == "" {
		return
	}
	f, ferr := os.OpenFile(inv.Log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if ferr != nil {
		return
	}
	defer f.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if inv.LogFormat == "json" {
		line, _ := json.Marshal(map[string]string{"level": "error", "msg": msg, "time": now})
		_, _ = f.Write(append(line, '\n'))
		return
	}
	_, _ = fmt.Fprintf(f, "time=%q level=error msg=%q\n", now, msg)
}
