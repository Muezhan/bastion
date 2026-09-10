# bastion

A minimal master/slave bastion. Slaves (clients) dial out to the master over
TLS and register under a name; the master's operator console lets you `use
<name>` to run shell commands on that slave and see the output. Works
through NAT/firewalls since the slave always initiates the connection.

Ships as two single-file binaries, built by CI:

- **`bastion-server`** — everything that runs on the master: `serve`,
  `add-client`, `remove-client`, `list-clients`, `gen-cert`, `fingerprint`.
- **`bastion-client`** — the slave agent that connects out to the master.

## How it works

- `bastion-server serve` listens for TLS connections, authenticates each
  slave by name + secret token, and gives you an interactive `bastion>`
  prompt.
- `bastion-client` connects out to the master, registers, then executes
  whatever commands the master sends via the OS shell and streams back
  stdout / stderr / exit code. It reconnects automatically with backoff if
  the link drops.
- Commands run as whatever user runs `bastion-client`. Run it as root/SYSTEM
  only if you intend for the master to have root on that box — there is no
  command allowlist, by design.

## Security model

- **Transport**: TLS. The master needs a certificate; slaves don't verify it
  against a CA (there isn't one) — instead they pin the master's certificate
  fingerprint (TOFU), so a MITM without that exact private key is rejected.
- **Auth**: each slave has a random per-client token; the master only ever
  stores `sha256(token)` in `clients.json`, never the token itself.
- **Trust direction**: the master is the trusted control point. Once a slave
  authenticates, the master can run *anything* on it. Treat the master host
  as your most sensitive asset — anyone who compromises it gets root
  (or whatever privilege the slave runs as) on every registered slave.
- This is not hardened for hostile internet exposure (no rate limiting, no
  audit log, single shared listener). Put the master behind a firewall
  allowing only your slave IPs if possible, and keep `clients.json` and the
  private key (`certs/master.key`) readable only by the master's own user.

## Getting the binaries

Download the latest release's `bastion-server-linux` and
`bastion-client-linux` from the repo's Releases page, or build them
yourself:

```bash
pip install -r requirements-build.txt
pyinstaller --onefile --name bastion-server server_main.py
pyinstaller --onefile --name bastion-client client_main.py
# binaries land in dist/
```

## Setup

1. On the master, generate a TLS cert and get its fingerprint:

   ```bash
   ./bastion-server gen-cert my-bastion
   ```

   This prints the fingerprint too (or run `./bastion-server fingerprint
   certs/master.crt` any time). Keep it — you'll pass it to every slave.

2. Register each client and capture its one-time token:

   ```bash
   ./bastion-server add-client web-01
   ```

3. Start the master:

   ```bash
   ./bastion-server serve --host 0.0.0.0 --port 8443
   ```

4. On each client machine, run the slave with the name, token, and pinned
   fingerprint from steps 1–2:

   ```bash
   ./bastion-client --host bastion.example.com --port 8443 \
       --name web-01 --token <token-from-step-2> \
       --fingerprint <fingerprint-from-step-1>
   ```

   Run this under a process manager (systemd, etc.) so it restarts on
   boot/crash.

## Using the master console

```text
bastion> list
web-01
db-01
bastion> use web-01
-- attached to 'web-01'; type 'exit' to detach --
web-01$ uptime
 23:10:01 up 4 days...
web-01$ exit
bastion> exit
```

Each line you type while attached runs as one shell command on that slave
(not a full interactive TTY/PTY — no `vim`, no job control, no live
streaming of a long-running process's output until it finishes).

## Layout

- `bastion/common.py` — message framing shared by both sides.
- `bastion/master_core.py` — master networking + operator console.
- `bastion/slave_core.py` — slave connection loop + command execution.
- `bastion/credentials.py` — add/remove/list client credentials.
- `bastion/tls.py` — self-signed cert generation and fingerprinting.
- `server_main.py` — `bastion-server` entry point (all subcommands above).
- `client_main.py` — `bastion-client` entry point.
- `.github/workflows/build.yml` — builds and smoke-tests both Linux binaries
  on every push, and attaches them to a GitHub Release when you push a
  `vX.Y.Z` tag.
