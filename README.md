# evm_signer_cli

The headless approver for `keystore_module` — what `evm_signer_ui` is in Basecamp, for a
`logosctl` daemon that has no window to show anything in.

`keystore_module` signs nothing without a human. A wallet *asks* (`request_approval`), and
only a configured **approver** may claim the request, read what the keystore says will be
signed, and answer with the vault password. `logosctl call keystore_module approve …` is
refused on purpose: the CLI is the host anchor, not a named module. `evm_signer_cli` is a named
module. It holds the role, shows every request over the event plane, and takes the decision
over method calls. Nothing else changes: the keystore still authors every line the human
reads, still checks the bundle id they echo back, and still hands the signatures only to the
requester that holds the receipt.

## A session

```bash
# once per daemon — configure is TOTAL, so restate the GUI surfaces alongside
logosctl call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"]}'
logosctl module load evm_signer_cli
```

Terminal 1, for as long as you are on duty:

```bash
logosctl watch evm_signer_cli --event prompt      # or without --event, to see settled/queue_changed too
```

```text
[12:00:01] evm_signer_cli :: prompt
  arg0: ksh_3f2a…
  arg1:
================================================================
SIGNING REQUEST  ksh_3f2a…
----------------------------------------------------------------
1.  Requested by: eth_wallet_backend
    What that app says this is for. Its own words — this signer
    cannot check any of it.
  Purpose (claimed by the requester): Send 0.1 WETH
----------------------------------------------------------------
2.  What you are signing
    The keystore's own reading of the request, shown in full and
    never shortened. This is what the signature will cover.
  Account: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  Commitment: 8c1e9f2b…
  1 item(s) to sign:
    [1] Transaction on chain 1
        To: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
        Value: 0
        Selector: 0xa9059cbb
        Data: 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045000000000000000000000000000000000000000000000000016345785d8a0000
----------------------------------------------------------------
3.  What this signer makes of section 2
    Decoded on this device from the lines above. Not part of what
    is signed, and every line says how sure it is.
  Interpreted: WETH — VERIFIED (this address is WETH on chain 1, and it declares this function)
    Function: transfer(address,uint256)
      dst: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
      wad: 100000000000000000
    In WETH units: 0.1 WETH
----------------------------------------------------------------
approve:  logosctl call evm_signer_cli approve ksh_3f2a… 8c1e… @/path/to/pwfile
reject:   logosctl call evm_signer_cli reject ksh_3f2a…
================================================================
```

Terminal 2, when you have read it:

```bash
umask 077; printf '%s\n' 'vault password' > /run/user/501/pw
logosctl call evm_signer_cli approve ksh_3f2a… 8c1e… @/run/user/501/pw
# → {"ok":true,"handle":"ksh_3f2a…","signed_count":1}
```

Three sections, in this order and never merged. Section 1 is the requester's own account of
what it wants and is worth nothing as evidence. Section 2 is what is actually signed, plus
the commitment over it — read that one. Section 3 is this module's own reading of section 2,
decoded offline from those very lines against a vendored ABI database, so it cannot describe
different bytes than the ones above it. It is additive, never a substitute, and it says how
sure it is: **VERIFIED** means the address is in the database *and* declares that function,
**UNVERIFIED** means a 4-byte selector matched and nothing ties it to the address. The
section keeps its place when there was nothing to decode — a message, a digest, or a
call this signer does not know — and says so, exactly as the Signer app does.

Below the decoder's reading of a leg, `token_list_module` may add what a token list on this
device calls the address, and the amount restated in its units. That is a **name, not a
check of the code**, and the line says so and names the list that answered — a user can add
a custom token, so a friendly symbol on a hostile address is reachable. It never touches the
tiers above: those belong to the ABI database, which backs a claim about code that no token
list makes.

`token_list_module` is an **optional** dependency. Absent is a normal state and costs only
those lines: this signer must come up on a device that has no token list at all.

`show` returns the same lines as `interpretation_lines`, so a machine consumer need not
re-parse the block.

Driving the wallet itself headlessly — `send`, `send_status`, the receipt sweep — is covered in
the [logos-eth-wallet-backend README](https://github.com/logos-co/logos-eth-wallet-backend#headless-operation-logosctl),
*Headless operation*.

## Methods

| Method | Does |
|---|---|
| `status()` | `{ok, held, identity, approvers, custodians, rendered, pending_count, last_error, hint}` — `held` says whether this module is a configured approver; `hint` is the exact `configure` command when it is not |
| `list()` | the keystore's queue summaries — never leg detail |
| `show(handle)` | claim `handle` for display: the keystore's lines, verbatim, this signer's `interpretation_lines`, plus the prompt text |
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

`evm_signer_cli` claims the head of the queue the moment it is offered, as `evm_signer_ui` does:
claiming means "this approver has it on screen", not "the human decided", and an
*unclaimed* offer is swept after sixty seconds while a claimed one waits for the human
indefinitely. With two approvers loaded it prefers whatever the other one already has on
screen, so the two converge rather than displace each other; an explicit `show <other>`
does displace, and `evm_signer_ui` never re-claims, so its Approve fails until its human
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

A daemon predating the completion-channel reservation publishes every method **reply** as a
`__logos_call_complete__` event on the module's channel, so a bare
`logosctl watch evm_signer_cli` also shows call results there. logos-protocol now reserves that
name, so on a current daemon a bare watch shows only this module's own events — the change is
not in `0.3.0-rc.1` or earlier. Nothing this module returns is secret either way;
`--event prompt` keeps the stream to what a human needs.

## What is deliberately absent

- **No unattended approval.** Every `approve` names the handle and the bundle id a human
  read. Automated tests use the `approver_probe` fixture in `logos-eth-wallet-backend`.
- **No signatures here.** Only the requester can collect them, with its receipt.
- **No self-enrolment.** `configure` is ungated and total; a module naming itself would be
  the exposure the keystore's spec defers, and two doing so would race. The operator names
  the roles; `status` says what to run.
- **No decoded calldata yet.** `evm_signer_ui` adds an offline interpretation of the calldata
  in the render lines (logos-tx-decoder); linking it into a Rust module is a follow-up.

## Build and test

```bash
nix build .#default            # the plugin
nix build .#install            # modules/evm_signer_cli/ for a logosctl session
nix build .#lgx-portable       # an installable .lgx (the -dev variant a daemon refuses is .#lgx)
(cd rust-lib && cargo test --no-default-features)   # the Logos-free helpers
./doctests/run.sh              # the headless spec, end to end against a real daemon
```
