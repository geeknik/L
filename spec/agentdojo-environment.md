# Isolated AgentDojo benchmark environment

Upstream source: https://github.com/ethz-spylab/agentdojo at commit
`089ed468cf3ed0322acc66b0211f26d9d90dbf60` (package version 0.1.35).
The upstream project is MIT licensed to its named authors; its license is
separate from this repository's MIT license and copyright. No upstream source
patches, dependency API shims, or task changes are part of this environment.

`benchmarks/agentdojo-requirements.lock` is a Python 3.12 benchmark-only,
hash-pinned environment. It is not this project's runtime dependency lock and
none of these SDK dependencies are added to the distributed TSD runtime.
Install it into an isolated virtual environment associated with the pinned
upstream checkout, never the TSD runtime environment.

The dependency inputs are exactly upstream `project.dependencies`, plus
PyNaCl 1.6.2 for the TSD gate and Hatchling 1.33.0 for building the upstream
editable package. Hatchling's explicit PEP 660 editable build requirement,
`editables~=0.3`, is also included; without it a no-build-isolation editable
install fails with `ModuleNotFoundError: editables`. The lock resolves and hashes
all transitive dependencies. Optional transformers, upstream dev and docs groups
are excluded. No model or provider credentials are part of the environment.

The upstream historical lock was not retained: pip-audit 2.10.1 reported 78
advisory entries in 17 packages. A fresh resolution within the declared upstream
dependency ranges was audited on 2026-11-15 with no known vulnerabilities.
This is an advisory snapshot, not proof of absence of vulnerabilities. The
patched dependency environment differs from upstream's historical environment;
results must identify both the source commit and this lock's hash. Dependency
imports and package compatibility do not prove identical benchmark behavior.

## Reproduction

Create the input requirements from the pinned checkout's pyproject metadata,
then append `pynacl==1.6.2`, `hatchling==1.33.0`, and `editables~=0.3`. Resolve with:

```sh
uv pip compile --python 3.12 --generate-hashes --upgrade requirements.in \
  --output-file benchmarks/agentdojo-requirements.lock
```

For subsequent reproduction, use the committed lock without resolving again:

```sh
uv pip sync --python "$AGENTDOJO_DIR/.venv/bin/python" --require-hashes \
  benchmarks/agentdojo-requirements.lock
uv pip install --python "$AGENTDOJO_DIR/.venv/bin/python" --no-deps \
  --no-build-isolation --editable "$AGENTDOJO_DIR"
uv pip check --python "$AGENTDOJO_DIR/.venv/bin/python"
uv tool run pip-audit==2.10.1 --require-hashes --disable-pip \
  --requirement benchmarks/agentdojo-requirements.lock
```

`AGENTDOJO_DIR` denotes an existing checkout at the exact commit above with a
Python 3.12 virtual environment already created. Editable installation binds to
that checkout, so keep its source unchanged during the frozen evaluation.

## Verified scope

Python 3.12.16, 79 installed packages including AgentDojo; `uv pip check`
reports compatibility. `agentdojo.task_suite` imports and `get_suites` works.
Only suite names and counts were read; no task prompts, solutions, model calls,
utilities or task execution were performed in this environment validation.

The pinned checkout exposes 97 registered user tasks for `v1.2.2`: workspace 40,
travel 20, banking 16, slack 21. All available version aliases expose the same
counts. The anticipated count of 86 was not confirmed; a smoke assertion for
86 failed. Any 86-task evaluation must separately define and freeze its selection
rather than silently dropping registered tasks. This environment validation does
not certify a task selection or benchmark result.
