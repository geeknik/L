"""L: A Trust-Typed Language for Agents — information-flow labels.

Every term carries three labels:
  - provenance: the chain of principals it passed through
  - integrity:  the lowest-trust input that influenced it
  - confidentiality: who may receive it
"""

from dataclasses import dataclass, field

INTEGRITY_ORDER = ['low', 'medium', 'high', 'critical']
CONFIDENTIALITY_ORDER = ['public', 'restricted', 'secret', 'top_secret']


@dataclass(frozen=True)
class Label:
    provenance: tuple[str, ...] = ()
    integrity: str = 'low'
    confidentiality: str = 'public'

    def __post_init__(self) -> None:
        if self.integrity not in INTEGRITY_ORDER:
            raise ValueError(f"unknown integrity level: {self.integrity!r}")
        if self.confidentiality not in CONFIDENTIALITY_ORDER:
            raise ValueError(f"unknown confidentiality level: {self.confidentiality!r}")

    def join(self, other: 'Label') -> 'Label':
        """Combine influences: union provenance, minimum trust, maximum secrecy."""
        return Label(
            provenance=tuple(sorted(set(self.provenance) | set(other.provenance))),
            integrity=min((self.integrity, other.integrity), key=INTEGRITY_ORDER.index),
            confidentiality=_max_of(CONFIDENTIALITY_ORDER, self.confidentiality, other.confidentiality),
        )

    def may_flow_to(self, clearance: str) -> bool:
        """True if data with this confidentiality may be received at the given clearance."""
        return CONFIDENTIALITY_ORDER.index(self.confidentiality) <= CONFIDENTIALITY_ORDER.index(clearance)

    def __repr__(self) -> str:
        return f"Label(prov={list(self.provenance)}, integ={self.integrity}, conf={self.confidentiality})"


def _max_of(order: list[str], a: str, b: str) -> str:
    return a if order.index(a) >= order.index(b) else b


def integrity_rank(level: str) -> int:
    return INTEGRITY_ORDER.index(level)


def integrity_at_least(a: str, b: str) -> bool:
    return integrity_rank(a) >= integrity_rank(b)


# A convenience: the label of untrusted input, which is the default for anything
# a model emits after reading the web.
LOW = Label(provenance=('untrusted',), integrity='low', confidentiality='public')
