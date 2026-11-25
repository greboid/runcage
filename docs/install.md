# Install

## Requirements

- Rootful Docker with runc. Rootless, userns-remap and other runtimes are not
  supported.
- Linux 6.4+ (the tmpfs uses `noswap`).

## Binary and runtime

Build a static binary and install it root-owned:

```sh
CGO_ENABLED=0 go build -trimpath -o secret-runc ./cmd/secret-runc
install -o root -g root -m 0755 secret-runc /usr/bin/secret-runc
```

Docker records the path in each container's hooks, so keep it stable;
replacing the binary in place is fine.

`/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "secrets": { "path": "/usr/bin/secret-runc" }
  }
}
```

Restart Docker. The wrapper runs `/usr/bin/runc`, or the first `runc` on
`PATH` that is not itself.

## Age identity

The identity is read on every container start, from the first that exists:

1. `/run/credentials/docker.service/age-key`: the credential below, unsealed
   by systemd for Docker (see "Unsealing once per Docker start").
2. `/etc/credstore.encrypted/age-key`: a systemd encrypted credential named
   `age-key` (host key, TPM2 or both), decrypted through systemd-creds'
   varlink socket. Needs systemd 258+ with `systemd-creds.socket` active.

   Generate a key and seal it without writing the plaintext to disk
   (`age-keygen` prints the public key on stderr):

   ```sh
   install -d -m 0700 /etc/credstore.encrypted
   age-keygen | systemd-creds encrypt --name=age-key --with-key=host+tpm2 - /etc/credstore.encrypted/age-key
   ```

   Print the recipient again later with
   `systemd-creds decrypt --name=age-key /etc/credstore.encrypted/age-key - | age-keygen -y`.

3. `/etc/credstore/age-key`: a plain age identity file.

Plain identity files (1 and 3) must be root-owned with no group or other
permissions.

### Unsealing once per Docker start

Without this, every container start unseals the credential. TPM2 unseals
serialise at about 0.7s each: 50 containers starting together took 36s, and
each start allows 45s for the identity, so hosts that start more than a few
dozen secret containers at once need it.

```sh
install -D -m 0644 contrib/systemd/docker.service.d/secret-runc.conf \
  /etc/systemd/system/docker.service.d/secret-runc.conf
systemctl daemon-reload
systemctl restart docker
```

systemd unseals the credential once when Docker starts and keeps it in
Docker's credential directory (root-only, read-only, `noswap` tmpfs) until
Docker stops. Restart Docker after changing the credential.

Then set up a service (see [Usage.md](Usage.md)).
