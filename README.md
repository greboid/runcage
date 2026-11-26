# Runcage

> [!CAUTION]
> This code is entirely written by an LLM.  I use it myself and it does
> what I expect, but I can't guarantee anything.\
> I find it useful and does something I couldn't find elsewhere.

Run cage is a thin OCI runtime wrapper around `runc` that decrypts a SOPS
document and provides its keys as files in `/run/secrets`, on a read-only
per-container tmpfs. It is configured with plain Compose `secrets:`, needs no
daemon or systemd service, and writes decrypted values only to the tmpfs,
not to the OCI config or `docker inspect`. See the [memory exposure limits](docs/Usage.md#limits). It works with [secret-env](https://git.mouse-lake.ts.net/greboid/secret-env)
unmodified.

## Example

```yaml
services:
  app:
    image: example/app
    runtime: runcage
    secrets:
      - source: app
        target: /run/sops/secrets.yaml

secrets:
  app:
    file: ./secrets.sops.yaml
```

`app` gets each key of `secrets.sops.yaml` as a read-only file in
`/run/secrets`. Without `runtime: runcage` it gets only the ciphertext.

## Documentation

- [Install](docs/install.md): binary, runtime registration and age identity.
- [Usage](docs/Usage.md): a worked example, options and troubleshooting.
- [Packaging](docs/packaging.md): notes for distribution packagers.

Requires rootful Docker with runc and Linux 6.4+.
