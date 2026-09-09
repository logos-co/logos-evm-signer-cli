# signer_cli

The headless approver for `keystore_module` — what `signer_ui` is in Basecamp, for a
`logosctl` daemon that has no window to show anything in.

`keystore_module` signs nothing without a human. A wallet *asks* (`request_approval`), and
only a configured **approver** may claim the request, read what the keystore says will be
signed, and answer with the vault password. `logosctl call keystore_module approve …` is
refused on purpose: the CLI is the host anchor, not a named module. `signer_cli` is a named
module. It holds the role, shows every request over the event plane, and takes the decision
over method calls. Nothing else changes: the keystore still authors every line the human
reads, still checks the bundle id they echo back, and still hands the signatures only to the
requester that holds the receipt.

## A session

```bash
# once per daemon — configure is TOTAL, so restate the GUI surfaces alongside
logosctl call keystore_module configure '{"approvers":["signer_ui","signer_cli"],"custodians":["keystore_ui","keystore_cli"]}'
logosctl module load signer_cli
```

Terminal 1, for as long as you are on duty:

```bash
logosctl watch signer_cli --event prompt      # or without --event, to see settled/queue_changed too
```

```text
[12:00:01] signer_cli :: prompt
  arg0: ksh_3f2a…
  arg1:
================================================================
SIGNING REQUEST  ksh_3f2a…
Requested by: eth_wallet_backend
----------------------------------------------------------------
Requester's claim (NOT verified by the keystore):
  Purpose (claimed by the requester): Send 0.01 ETH
----------------------------------------------------------------
What will be signed (the keystore's own words):
  Account: 0xf39F…
  Commitment: 8c1e…
  1 item(s) to sign:
    [1] Transaction on chain 11155111
        To: 0x7099…
        Value: 0x2386f26fc10000 (10000000000000000)
        …
----------------------------------------------------------------
approve:  logosctl call signer_cli approve ksh_3f2a… 8c1e… @/path/to/pwfile
reject:   logosctl call signer_cli reject ksh_3f2a…
================================================================
```

Terminal 2, when you have read it:

```bash
umask 077; printf '%s\n' 'vault password' > /run/user/501/pw
logosctl call signer_cli approve ksh_3f2a… 8c1e… @/run/user/501/pw
# → {"ok":true,"handle":"ksh_3f2a…","signed_count":1}
```

The two lists are the keystore's and are never merged: the *claim* is the requester's own
account of what it wants and is worth nothing as evidence; the *render* is what is actually
signed, plus the commitment over it. Read the second one.

## Methods

| Method | Does |
|---|---|
| `status()` | `{ok, held, identity, approvers, custodians, rendered, pending_count, last_error, hint}` — `held` says whether this module is a configured approver; `hint` is the exact `configure` command when it is not |
| `list()` | the keystore's queue summaries — never leg detail |
| `show(handle)` | claim `handle` for display: the keystore's lines, verbatim, plus the prompt text |
| `approve(handle, bundle_id, password)` | the human said yes to the request on screen; `{ok, handle, signed_count}` |
| `reject(handle)` | the human said no; `bool` |
| `refresh()` | re-read the queue now, then answer as `status` does |

`approve` binds three things and refuses before the password is used if any is off: the
handle must be the one on screen, the bundle id must be the one shown, and the request is
re-claimed from the keystore so a record another approver displaced, or one that settled
meanwhile, is caught here rather than by a spent password. The reply is a **count**: an
approver causes signatures to exist and never receives them.

## Events

| Event | Says |
|---|---|
| `prompt(handle, text)` | a request is on screen; `text` is the whole block above |
| `settled(handle, state)` | `approved` / `rejected`, relayed from the keystore; `gone` when the poll finds a request vanished — the keystore never announces a cancelled or expired one |
| `queue_changed(count)` | how many are waiting |

`signer_cli` claims the head of the queue the moment it is offered, as `signer_ui` does:
claiming means "this approver has it on screen", not "the human decided", and an
*unclaimed* offer is swept after sixty seconds while a claimed one waits for the human
indefinitely. With two approvers loaded it prefers whatever the other one already has on
screen, so the two converge rather than displace each other; an explicit `show <other>`
does displace, and `signer_ui` never re-claims, so its Approve fails until its human
dismisses.

## Arguments

- **Passwords:** `@file` (out of shell history and `ps`) or `str:…`. Never bare — `1234`
  is coerced to a number and the call is refused. A file written with `echo` ends in a
  newline; exactly one is stripped.
- **Handles and bundle ids:** as printed. A bundle id may be given with or without `0x`.
  Anything `logosctl` could read as a number — all digits, or `0x…` — needs `str:`; a real
  64-hex bundle id is safe as written.
- **Addresses** elsewhere in the stack: bare hex without `0x`, which `logosctl` would parse
  as a number.

The daemon logs only the argument count of a call, never a value; this module never logs,
emits or stores a password.

Note that the daemon publishes every method **reply** as a `__logos_call_complete__` event on
the module's channel, so a bare `logosctl watch signer_cli` also shows call results. Nothing
this module returns is secret; `--event prompt` keeps the stream to what a human needs.

## What is deliberately absent

- **No unattended approval.** Every `approve` names the handle and the bundle id a human
  read. Automated tests use the `approver_probe` fixture in `logos-eth-wallet-backend`.
- **No signatures here.** Only the requester can collect them, with its receipt.
- **No self-enrolment.** `configure` is ungated and total; a module naming itself would be
  the exposure the keystore's spec defers, and two doing so would race. The operator names
  the roles; `status` says what to run.
- **No decoded calldata yet.** `signer_ui` adds an offline interpretation of the calldata
  in the render lines (logos-tx-decoder); linking it into a Rust module is a follow-up.

## Build and test

```bash
nix build .#default            # the plugin
nix build .#install            # modules/signer_cli/ for a logosctl session
nix build .#lgx-portable       # an installable .lgx (the -dev variant a daemon refuses is .#lgx)
(cd rust-lib && cargo test --no-default-features)   # the Logos-free helpers
./doctests/run.sh              # the headless spec, end to end against a real daemon
```
