# L: A Trust-Typed Language for Agents

L separates an AI agent's proposed actions from the authority to execute them.
It combines a small, typed message language with a deterministic security gate
and a local enforcing host. Python and Rust implementations share language,
wire-format, and signed-authority contracts.

The host assigns trust labels to inputs. After reading untrusted content, an
agent cannot perform an action requiring higher integrity unless a trusted
operator signs an endorsement of that exact action. Model-generated text cannot
create authority, change its own labels, or turn quoted data into executable acts.

## How it works

1. **Register tools and trust keys.** The host binds each tool to its principal,
   definition hash, and confidentiality policy. Trusted public keys have explicit
   scopes, signing roles, and integrity ceilings.
2. **Issue a capability.** An offline authority signs a grant for a particular
   session, tool, scope, required integrity, and expiration time.
3. **Observe inputs.** The host tracks provenance, confidentiality, and the lowest
   integrity of the inputs seen during the session.
4. **Authorize an action.** The gate verifies the proposed `DIRECT` against the
   live grant. If integrity is insufficient, it requires a signed, one-use
   endorsement bound to the exact UTF-8 action bytes.
5. **Execute through the host.** Only validated arguments reach the registered
   tool. Revocation removes the grant and approvals while retaining replay
   protection for the session.

Capabilities and endorsements use Ed25519 through established cryptographic
libraries. There are no built-in trusted identities or automatic approvals.

## Get started

The Python package requires Python 3.12 or newer. The enforcing host and process
adapters require a POSIX system. Use [uv](https://docs.astral.sh/uv/) to install the
locked project environment from source:

```bash
git clone https://github.com/geeknik/L.git
cd L
uv sync --locked
```

Run a local demonstration of the security boundary:

```bash
uv run --locked python -m demos.security_demo
```

The demo refuses an unendorsed action, executes the exact approved callback once,
and refuses another action after revocation. It uses an ephemeral authority and
a fixed local callback; it is not a production signing policy.

To exercise the actual host and offline authority CLIs:

```bash
uv run --locked python demos/owned_host.py
```

This creates temporary keys and configuration, tests authorized file effects and
negative cases, and removes its temporary state on normal completion. Follow the
[operator guide](spec/owned-host-operations.md) to provision a real deployment
with separate OS identities and protected configuration.

## Tools and libraries

| Component | Purpose |
| --- | --- |
| `tsd-host` | Enforcing service over private inherited stdin/stdout pipes; dispatches configured tools after authorization |
| `tsd-authority` | Offline key initialization, public-key recovery, and signing of explicitly reviewed statements |
| `gate.host.LocalHost` | Python integration API for trusted model and tool adapters |
| `gate.security.SecurityGate` | Stateful authorization API; verifies signed authority and proposed actions |
| `rust/` | Rust language, wire-format, authority, and security-gate counterparts |
| `tsd-scan` | Structural language validation; does not authorize or execute tools |
| `tsd-proxy` | Structural MCP/JSON-RPC inspection scaffold; does not forward upstream requests or enforce signed authority |

For CLI options, run `uv run --locked tsd-host --help` or
`uv run --locked tsd-authority --help`. The
[host protocol](spec/owned-host.md) defines configuration and request schemas;
the [library contract](spec/local-host.md) describes direct Python integration.

## The language

L has seven acts: `ASSERT`, `QUERY`, `DIRECT`, `COMMIT`, `GRANT`, `REVOKE`, and
`ENDORSE`. Text inside a payload remains data. References combine a principal
with a content hash; a hash alone does not authenticate authority.

A proposed tool action looks like this:

```text
DIRECT cap:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  (scope=files.read, exp=60, from=operator)
  call tool:(srv:files, sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
  {path: "/reports/summary.txt"}
```

The hashes above are illustrative. Execution requires a live signed grant with
the actual session and tool bindings; parsing this text grants no permission.
Model-written `GRANT`, `REVOKE`, and `ENDORSE` cannot change security-gate state.
That state changes only through verified signed statements.

Tool parameters are strings or nonnegative integers bounded by `i64::MAX`.
Duplicate keys and unsupported value types are rejected. Source strings preserve
backslashes literally and represent an embedded quotation mark by doubling it.
The structural checker validates TTL syntax; the security gate also enforces the
signed absolute expiration and grant lifetime.

See the [calculus](CALCULUS.md), [principal grammar](spec/principals.md),
[source-string rules](spec/source-strings.md), and
[canonical binary wire format](spec/wire.md) for the complete contracts.

## Security boundaries

- All influencing inputs and tool effects must pass through trusted host adapters.
  The gate cannot detect inputs that an adapter hides from it.
- Integrity accumulates conservatively across the session. Endorsement permits
  one exact action; it does not raise the session's integrity.
- Sessions are process-local and never resumed. Restart creates a fresh subject;
  old grants and approvals cannot authorize the new session.
- Keep signing keys and wrapping material under an operator identity isolated
  from model/tool processes. Filesystem custody does not protect against root or
  compromise of that operator account.
- Process adapters bound communication and process-group lifetime. They are not
  an OS sandbox; deployer-controlled isolation must contain untrusted tools and
  detached descendants.
- A signed tool is not necessarily a safe tool. Review its implementation,
  configuration, clearances, and side effects. Do not automatically retry after
  an uncertain or partially completed effect.

The [security contract](spec/security-gate.md) and
[deployment guide](spec/deployment.md) define these assumptions. The project does
not claim a mechanized proof, formal non-interference guarantee, or protection
for execution outside the enforcing host.

## Development and verification

Full verification also requires Rust with Clippy. From the repository root:

```bash
uv sync --locked
uv run --locked python scripts/verify.py
```

The runner checks generated limits, strict Python typing, Python and Rust tests,
Clippy, conformance vectors, exploit contracts, differential fuzzing, and package
builds with isolated installation. CI also audits locked dependencies.

Useful focused commands:

```bash
uv run --locked python -m unittest tests.test_security_gate
cargo test --locked --manifest-path rust/Cargo.toml --test security_tests
uv run --locked python conformance/diff_fuzz.py 500 --seed 0
uv run --locked tsd-scan demos/full_demo.tsd
```

The scanner's success means structural acceptance only. Shared signed vectors
exercise cross-language security behavior; parser agreement alone does not prove
stateful authorization. Synthetic timings measure throughput, while the
[utility experiment](spec/utility-experiment.md) evaluates paired task outcomes
under a declared sandbox policy.

## Documentation

- [Design](DESIGN.md): project goals and architectural direction.
- [Operator guide](spec/owned-host-operations.md): provisioning, signing, rotation,
  and recovery.
- [Authority lifecycle](spec/authority-lifecycle.md): encrypted custody and session
  retirement.
- [Limits](spec/limits.md): shared bounds on parsing, execution, and state.
- [Verification](spec/verification.md): command outcomes and failure handling.

## License

[MIT](LICENSE).
