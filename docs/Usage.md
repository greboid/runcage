# Usage

How to give a Compose service secrets with Run cage. This assumes the
binary is installed, the `secrets` runtime is registered and the host has an
age identity (see [install.md](install.md)).

## Example

A service that needs a database password and an API key.

### 1. Get the host's recipient

Documents are encrypted to the age public key of every host that will run
them:

```sh
sudo systemd-creds decrypt --name=age-key /etc/credstore.encrypted/age-key - | age-keygen -y
# or, with a plain identity file
sudo age-keygen -y /etc/credstore/age-key
```

This prints a recipient such as `age1qqqq...`. It is a public key and can be
kept in the repository.

### 2. Write and encrypt the document

The document is a flat YAML mapping of names to string values. Each name
becomes a file in `/run/secrets`, so names must match `[A-Za-z_][A-Za-z0-9_]*`.

```sh
cat > secrets.yaml <<'EOF'
DATABASE_PASSWORD: "correct horse battery staple"
API_KEY: "abc123"
EOF
sops --encrypt --age age1qqqq... --input-type yaml --output-type yaml secrets.yaml > secrets.sops.yaml
rm secrets.yaml
```

To avoid writing the plaintext to disk, create the encrypted file directly
with `sops edit secrets.sops.yaml` after adding a `.sops.yaml` creation rule
for the recipient. Quote every value: numbers, booleans and nulls are
rejected.

Commit `secrets.sops.yaml`; it only contains ciphertext.

### 3. Add it to the Compose file

```yaml
services:
  app:
    image: example/app
    runtime: runcage
    user: "65532:65532"
    secrets:
      - source: app
        target: /run/sops/secrets.yaml

secrets:
  app:
    file: ./secrets.sops.yaml
```

- `runtime: runcage` runs the container through Run cage.
- The secret's `target` must be directly under `/run/sops/`. The filename does
  not matter.
- `file` is relative to the Compose file.

### 4. Start and check

```sh
docker compose up -d
docker compose exec app ls -l /run/secrets
```

```
-r--------    1 65532    65532    6 Nov 25 21:20 API_KEY
-r--------    1 65532    65532   28 Nov 25 21:20 DATABASE_PASSWORD
```

The files are owned by the container's user, readable only by it, on a
read-only tmpfs. `/run/sops` does not exist inside the container.

## Reading the secrets

Applications can read `/run/secrets/<NAME>` directly. Values are written
exactly as stored, with no trailing newline added.

Applications that take configuration from environment variables can use
[secret-env](https://git.mouse-lake.ts.net/greboid/secret-env) as the
entrypoint, with a discovery directory:

```ini
[exec]
path = /usr/bin/app

[discovery]
directory = /run/secrets
```

Each file becomes a variable of the same name. If the container is started
without Run cage, `/run/secrets` does not exist and secret-env starts the
application with no secrets.

## Options

Set as service annotations:

```yaml
services:
  app:
    annotations:
      g5d.dev/runcage/keys: DATABASE_PASSWORD
      g5d.dev/runcage/owner: "1000:1000"
```

| Annotation | Default | Meaning |
|---|---|---|
| `g5d.dev/runcage/keys` | every key | Comma-separated keys to write. Each must exist in the document. |
| `g5d.dev/runcage/owner` | the container's `user` | `uid:gid` for the files, numeric only. |

Set the owner when the container starts as root and its entrypoint drops to
another user: by default the files are owned by root and the dropped user
cannot read them.

`g5d.dev/runcage/secrets` is reserved for the runtime. Do not set it in
Compose. No other `g5d.dev/runcage/*` service options are supported.

## Sharing a document

Several services can use the same document; each gets its own copy of the
selected keys:

```yaml
services:
  web:
    runtime: runcage
    annotations:
      g5d.dev/runcage/keys: API_KEY
    secrets:
      - source: shared
        target: /run/sops/secrets.yaml
  worker:
    runtime: runcage
    annotations:
      g5d.dev/runcage/keys: DATABASE_PASSWORD,API_KEY
    secrets:
      - source: shared
        target: /run/sops/secrets.yaml

secrets:
  shared:
    file: ./secrets.sops.yaml
```

A service can use only one document.

## Changing secrets

```sh
sops edit secrets.sops.yaml
docker compose restart app
```

The document is decrypted on every container start, so a restart picks up the
change. Running containers keep the values they started with.

To add a host, re-encrypt to its recipient as well:

```sh
sops updatekeys secrets.sops.yaml   # after adding the recipient to .sops.yaml
# or
sops --rotate --in-place --add-age age1new... secrets.sops.yaml
```

## Without Run cage

If `runtime: runcage` is left out, the container gets the encrypted document
at `/run/sops/secrets.yaml` and no `/run/secrets`. Nothing is decrypted, so
this is safe, but the application gets no secrets. If `runtime: runcage` is
set on a host where the runtime is not registered, Docker refuses to start
the container.

## When a container will not start

Errors appear in the `docker compose up` or `docker start` output, ending
with `runcage: <reason>`. Common reasons:

| Message | Cause |
|---|---|
| `cannot read age identity: ...` | No identity installed, or a plain identity file is not root-owned `0600`/`0400`. |
| `data key recovery failed: the age identity cannot decrypt this document` | The document is not encrypted to this host's recipient. |
| `integrity check failed: MAC mismatch ...` | The document was edited without sops, or is corrupt. |
| `secret "X" has a integer value; all values must be YAML strings` | Quote the value in the document. |
| `key "X" not in document` | A key in `g5d.dev/runcage/keys` is missing from the document. |
| `key "x.y" cannot be a secret file name ...` | Rename the key, or leave it out with `g5d.dev/runcage/keys`. |
| `more than one document under /run/sops` | Only one document per service. |
| `existing mount at /run/secrets conflicts with /run/secrets` | Remove the other mount (for example a `tmpfs:` entry) at or under `/run/secrets`. |
| `cannot open /run/secrets: ...` | The image has `/run` as a symlink. |
| `secrets are not supported with user namespaces` | The daemon uses userns-remap, which is not supported. |

## Limits

- At most 512 keys per container, 64 KiB per value and 1 MiB in total.
- `docker checkpoint` is allowed only when runc's saved state identifies the
  container as created or restored **without secrets** by Run cage. A container
  created before this classification was introduced must be recreated before
  it can be checkpointed, even if it never used secrets.
- Restore refuses bundles with secret hooks, a SOPS marker, or a `noswap`
  tmpfs at `/run/secrets`. Only restore trusted checkpoint images: the check
  classifies the bundle, not the contents of a CRIU image. Keep bundles under
  runtime control and serialize lifecycle operations on the same container ID.
- For checkpoint and restore, put options before the single container ID.
  Unknown options or an ambiguous target are refused.
- Anyone with access to the Docker socket, or root on the host, can read the
  secrets, for example with `docker exec`.
- Before reading an identity or document, the hook disables kernel core dumps
  (`PR_SET_DUMPABLE=0` and both `RLIMIT_CORE` limits zero) and locks its
  memory (`mlockall` with `MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT`), so the age
  identity, data key and plaintext are not swapped. If any call fails, startup
  stops. These settings apply to the hook, not the application.
- The [recommended build](install.md#binary-and-runtime) uses Go's experimental
  `runtime/secret.Do` on Linux amd64 and arm64. It clears temporary stack and
  register data on return; unreachable heap data is cleared when collected,
  not necessarily before hook exit.
- Locked memory is still written to disk by hibernation.
- The application can still expose the values through its own core dumps,
  swap or anything it writes out.
- Key names, recipients and other SOPS metadata are not encrypted.
