# Packaging

Notes for distributing Run cage as a distribution package or image. The
binary has no configuration file and no persistent state; everything below
is about where files go and what a package must not do.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -o runcage ./cmd/runcage
```

- The Go version is set in `go.mod`. The result is a static binary with no
  runtime library dependencies.
- `go test ./...` runs the unit tests. They need Linux with `openat2` and
  unprivileged temporary directories; build sandboxes whose seccomp policy
  blocks `openat2` will fail them.

## Files

| Path | Mode | Notes |
|---|---|---|
| `/usr/bin/runcage` | `0755 root:root` | Required. |
| `/usr/lib/systemd/system/docker.service.d/runcage.conf` | `0644` | Optional, from `contrib/systemd/docker.service.d/`. Systemd hosts only. |
| `LICENSE`, `README.md`, `docs/` | `0644` | CC0 1.0. |

- The binary must be owned by root and writable only by root: Docker runs it
  as root for every container using the runtime, and it records its own path
  as the OCI hook for those containers.
- Another install path is fine, but keep it stable across upgrades and use
  the same path in the runtime registration.
- Install the Docker drop-in in the vendor unit directory, not
  `/etc/systemd/system`, so administrators can override it. It only imports
  a credential named `age-key` and does nothing if none exists, so it is safe
  to ship enabled.

## Runtime registration

Docker learns about the runtime from `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "runcage": { "path": "/usr/bin/runcage" }
  }
}
```

- Do not overwrite or rewrite `daemon.json` from a package: it is
  administrator-owned and Docker refuses to start if it is invalid. Tell the
  administrator to add the entry (post-install message, documentation).
- Do not also pass `--add-runtime runcage=...` to dockerd: Docker refuses to
  start when a runtime is defined both ways.
- Keep the runtime name `runcage`. Compose files select it with
  `runtime: runcage`, so a different name makes them non-portable.
- Docker must be restarted after the entry is added.
- Do not make it Docker's default runtime. Containers without a SOPS document
  pass through unchanged, but the default should stay an explicit choice.

## Dependencies

Required at runtime:

- Rootful Docker using runc. Run cage runs `/usr/bin/runc`, or the first
  `runc` on the daemon's `PATH` that is not itself. If runc is installed
  elsewhere, make sure it is on `PATH` for containerd.
- Linux 6.4 or later (the secrets tmpfs uses `noswap`).

Optional:

- systemd 258 or later with `systemd-creds.socket` active, for identities
  stored as systemd encrypted credentials.
- systemd 254 or later for the Docker drop-in (`ImportCredential=`).

Not needed: `sops`, `age`, or `systemd-creds` executables. Decryption is in
process and credentials are decrypted over varlink. `sops` and `age-keygen`
are only needed by administrators to create documents and keys.

Without systemd, only the plain identity file (`/etc/credstore/age-key`) is
available. Skip the drop-in.

## Fixed paths

These are compiled in and cannot be changed by packaging:

| Path | Use |
|---|---|
| `/run/credentials/docker.service/age-key` | Identity unsealed by the Docker drop-in |
| `/etc/credstore.encrypted/age-key` | systemd encrypted credential, name `age-key` |
| `/etc/credstore/age-key` | Plain identity file |
| `/run/sops/` | Container path marking the SOPS document |
| `/run/secrets` | Container path of the decrypted secrets |

## What a package must not do

- Generate, install or back up an age identity. Keys are host-specific and
  created by the administrator (see [install.md](install.md)).
- Create `/etc/credstore*` contents, or relax the permissions of existing
  directories there.
- Restart Docker from install or upgrade scripts. Running containers would be
  restarted with it.

## Upgrades and removal

- Upgrades need no migration. The binary is only executed when a container
  is created, so replacing it in place does not affect running containers;
  they use the new version on their next start.
- After removal, containers that use `runtime: runcage` fail to start until
  the runtime is reinstalled or removed from `daemon.json` and from their
  Compose files. Remove the `daemon.json` entry as part of uninstalling.
- No files are left behind at runtime: secrets live on per-container tmpfs
  mounts that disappear with the container.
