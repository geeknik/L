# L: A Trust-Typed Language for Agents (Design v0)

Nov 13, 2026 · @Brian Carpenter

> This document describes the design target. The implemented security boundary
> is defined in [spec/security-gate.md](spec/security-gate.md), with local host
> integration in [spec/local-host.md](spec/local-host.md). The scanner and MCP
> proxy perform structural validation only. These contracts do not imply an
> end-to-end security proof.

## Thesis

L is a typed language of speech acts with information-flow labels, enforced by a deterministic gate that sits between every model and everything it can touch. "L" is a working name.

Natural language lets an agent say things it has no authority to say. L makes those utterances ungrammatical. It is the constructive half of the Trust-State Desync (TSD) class: each TSD sub-mechanism maps to a sentence L refuses to parse or execute.

L is machine-native and human-auditable. It has a canonical binary form and a lossless, deterministic rendering to readable text. It is not an opaque channel.

## Landscape

The cryptographic and authorization layers are already being standardized, so L does not compete there. Nobody owns meaning: which utterances are commands, which are data, and what untrusted data is allowed to cause.

| Layer | Who covers it | What it leaves open |
| --- | --- | --- |
| Signing and identity | [MCPS IETF draft](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/): agent identity, per-message signatures, tool-definition integrity, replay protection | Its scope excludes tool safety analysis |
| Capabilities | [AAP IETF draft](https://www.ietf.org/archive/id/draft-fane-opena2a-aap-02.html): typed authorization entries with attenuation rules for delegation | What a directive means and what data may cause |
| Agent-to-agent | [A2A 1.0](https://authzed.com/learn/agent-to-agent-communication-guide-google-a2a-protocol) (March 2026): discovery, tasks, messages | Authorization is deferred to ordinary web security schemes |

L is the semantic layer above these. The operator chose an in-house authority
integration for 1.0: our signed statement protocol uses established Ed25519
libraries, not novel cryptography. Compatibility with these drafts is not claimed.

## The stack

The table describes architectural responsibilities, not completion status.

| Layer | What it is | Build or borrow |
| --- | --- | --- |
| 0. Transport | MCP, A2A | Borrow unchanged |
| 1. Crypto | Established signatures; in-house signed authority statements | Borrow primitives, build authority integration |
| 2. Language | Speech acts plus labels | Build |
| 3. Gate | Reference monitor that verifies every act before it executes | Build |
| 4. Projection | Lossless rendering to readable text and audit logs | Build |

## The language

**Seven acts, closed set.** `ASSERT`, `QUERY`, `DIRECT`, `COMMIT`, `GRANT`, `REVOKE`, `ENDORSE`. Natural language may appear only inside a quoted payload, which no rule can promote to an act.

**Three labels on every term.**

- Provenance: the chain of principals it passed through.
- Integrity: the lowest-trust input that influenced it.
- Confidentiality: who may receive it.

**Four rules that carry the weight.**

1. The runtime assigns labels. The model never writes its own. This is the design's central constraint.
2. A `DIRECT` executes only if its capability admits the directive's integrity level. Anything a model emits after reading low-integrity data inherits that level.
3. Raising integrity requires an explicit `ENDORSE` signed by a principal with authority. Human approval becomes a logged act in the language, not a UI click.
4. Every reference is `(principal, content hash)` and every act expires. An approval binds to the exact hash approved, which closes TSD-1 and TSD-4 structurally.

**Deliberate limits.** Not Turing-complete, bounded depth and size, one canonical encoding, total policy evaluation.

**Parameter value grammar and type contract.** A `DIRECT` act carries a tool-call parameter map `{key: value}`. The shared contract for both implementations: quoted strings and bare identifiers are string values; integer tokens and decimal-only digit strings (including ≥8-digit sequences the tokenizer classifies as `HASH`) are integer values bounded to `0..=i64::MAX`; unsupported value kinds such as `<opaque>` payloads are rejected at parse time, never silently dropped — a dropped argument would let the gate approve a directive whose arguments differ from the supplied program. Python represents values as `str`/`int`; Rust uses a `ParamValue` enum (`Str`/`Int`). Neither implementation may skip or coerce unknown token kinds.

Illustrative surface form (syntax not final):

```
DIRECT  cap:7f3a…(scope=fs.read, exp=60s, from=user:g)
        call tool:(srv:9c1e…, sha256:ab44…) {path: "/logs"}
ASSERT  ev:relayed(srv:9c1e…) data:<opaque, non-promotable>
```

## The hard problem

Grammar cannot stop a model from being persuaded by what it reads. The model's cognition is the laundering point: tainted data goes in and a clean-looking directive comes out. Rule 2 handles this by assuming laundering always happens.

The price is utility. An agent that has read the web cannot take high-integrity actions without endorsement. Policy tunes this per deployment. The design stands or falls on whether real workflows survive it.

## How models speak it

Models emit L through constrained decoding against the grammar. The model proposes acts; the gate labels and verifies them. Legacy untyped traffic is lifted to a lowest-integrity `ASSERT`, so L works with zero cooperation from servers.

## Proof

Three artifacts make the safety claim checkable.

- A mechanized non-interference theorem for the core calculus: low-integrity input cannot cause a high-integrity action without an `ENDORSE`.
- Two independent implementations (Python reference and Rust counterpart, with vetted crypto libraries), differentially fuzzed against each other to test the one-parse property.
- Forgeglass as the conformance suite.

## Adoption

The path runs from a tool one host can install today to a language models speak natively.

1. **An enforcing host integration for v1.0.** Every influencing input must lower runtime trust as needed, and every real tool execution must require SecurityGate authorization. The current MCP scaffold is only a structural probe and does not meet this milestone.
2. **Free TSD scanner.** Each advisory cites the invariant line violated and the L rule that prevents it.
3. **Ship as an MCP extension, not a rival standard.** The 2026-07-28 MCP revision gave [extensions](https://aaif.io/?p=1382) reverse-DNS identifiers, separate repos, delegated maintainers and independent versioning.
4. **IETF draft for the calculus**, positioned as the semantic complement to the signing and authorization drafts.
5. **Publish a large corpus of well-formed transcripts.** Once it is in training data, models speak L natively. That is the actual post-human step.

## Money and governance

Give the language away to a foundation early. A standard owned by one company gets forked or ignored. Sell the production gate, conformance certification, and audit tooling.

## Wild success, and what to refuse

L transcripts become the record of what an agent was told, by whom, and on what evidence. Auditors, insurers, and procurement require them. The Tertium use case falls out directly: a benefits decision carries its evidential chain.

Refused outright:

- Opaque latent channels
- Novel cryptography
- A general-purpose programming language
- Any feature that needs model cooperation to be safe

## Kill criteria and first 30 days

Stop or redirect if either holds:

- The enforcing host blocks the exploits but breaks more than the approved fraction of benign benchmark tasks. The frozen sandbox experiment requires baseline task success of at least 50% and a one-sided 95% upper bound on harmful paired regressions of at most 5 percentage points. See `spec/utility-run.md` for the approved policy, population and limits; this does not measure production endorsement costs.
- An incumbent ships labels with runtime-assigned integrity first. Then contribute the proof and the conformance suite to theirs.

First 30 days:

- [ ] One-page calculus
- [ ] Python gate
- [ ] Two exploit demos (TSD-1 and TSD-4 failing at the gate)
- [ ] Utility measurement on a standard agent benchmark

The utility number decides everything else.

## Sources

Landscape claims come from web search results on 2026-11-13. The pages were not opened in full, so verify before citing externally.

- [MCPS: Cryptographic Security Layer for MCP (IETF draft)](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)
- [OpenA2A Agent Authorization Protocol, draft 02 (IETF draft)](https://www.ietf.org/archive/id/draft-fane-opena2a-aap-02.html)
- [AuthZed guide to A2A 1.0](https://authzed.com/learn/agent-to-agent-communication-guide-google-a2a-protocol)
- [Agentic AI Foundation post on the 2026-07-28 MCP revision](https://aaif.io/?p=1382)
- Trust-State Desync (TSD) v1, in this project: `claude/trust-state-desync-class-v1.md`
