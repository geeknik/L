# Source string literals

L source strings preserve their Unicode content literally, including backslashes,
line breaks and whitespace. Backslash sequences are not JSON escapes. To put a
quotation mark inside a source string, double it: `"a""b"` represents `a"b`.
An empty string is `""`; a single quotation mark is `""""`.

After the opening quote, scan until a quote not immediately followed by another
quote. A consecutive pair inside the literal appends one quote and continues;
a lone quote closes the literal. Missing closure is a parse error. Tokenization
remains bounded by the existing UTF-8 source and token limits. No normalization,
payload promotion or backslash interpretation is introduced.

This extends previously invalid adjacent-quote syntax. Existing valid literals
retain their bytes and meaning, including literal backslash-n. Source producers
must use `"` + value.replace(`"`, `""`) + `"`, not JSON string serialization.
Signed approvals continue to bind exact source bytes, never reconstructed text.
The canonical binary/JSON AST transport has its own unchanged escaping rules.

Shared regression vectors: `conformance/source_string_vectors.json`.
