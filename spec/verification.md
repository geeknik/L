# Verification outcome contract

Every verification command exits nonzero on an unexpected outcome, timeout,
missing input, or internal exception (I7). No empty/truncated result establishes
success. The single `scripts/verify.py` runner stops at the first failed command.

The five checked-in synthetic benchmark fixtures are structural positive
controls. All must parse nonempty programs and pass structural validation for
the smoke command to exit zero. Denials and exceptions are measured and printed,
but are failures of these controls, not successful utility outcomes. A future
real utility experiment needs a separate frozen protocol and may legitimately
measure refusals; its results must not change this smoke-test contract.
