# Principal text grammar

This contract governs principal references in the current Python and Rust text
parsers. It resolves their prior disagreement on bare principals and prohibits
silently concatenating separate tokens into an identity (I4, I5, I7).

```
principal = IDENT (":" segment)*
segment   = IDENT | NUMBER | HASH
reference = "(" principal "," "sha256" ":" HASH ")"
          | "(" "sha256" ":" HASH ")"
endorse   = "ENDORSE" reference "by" ":" principal
```

`IDENT`, `NUMBER`, and `HASH` are the existing ASCII word token kinds. Each
segment is a single nonempty token containing only ASCII letters, digits, or
underscore; act keywords remain reserved. Numeric and hexadecimal suffixes
are retained literally, including leading zeros and case. Bare principals
such as `admin` and `reviewer` are valid. Empty segments, trailing colons,
and adjacent words without a colon are rejected, never joined or discarded.
An `ENDORSE` requires an explicit signer; omitting `by:` is a parse error.
This is syntax validation, not authentication or endorsement authority.

For compatibility with the existing AST, a reference with exactly one `HASH`
suffix stores that suffix in `Principal.hash`; other reference forms use the
existing zero-filled placeholder. Signers and capability issuers retain their
existing zero-filled placeholder. These fields do not establish cryptographic
identity. The content-only `(sha256:HASH)` shorthand produces principal
`anon` as a structural compatibility path. Only the complete shorthand selects
that form. A named reference may use `sha256` as its first principal segment,
as in `(sha256:files, sha256:abcdef00)`. SecurityGate explicitly rejects
anonymous references.

Outside payloads and comments, whitespace is exactly ASCII space, tab, line
feed, vertical tab, form feed, or carriage return (U+0020 and U+0009–U+000D).
Other Unicode separators and control characters are not whitespace tokens.
Payloads retain their original characters. Whitespace may separate tokens,
but cannot join two words into one principal segment.

Shared accept/reject vectors are in `conformance/principal_vectors.json`.
