"""TDD test suite for L: A Trust-Typed Language for Agents v1.0."""

import unittest
import sys
sys.path.insert(0, '/home/geeknik/dev/tsd')

from lang.parser import parse, ParseError, tokenize
from lang.ast import (
    AssertAct, QueryAct, DirectAct, CommitAct, GrantAct, RevokeAct, EndorseAct,
    Principal, Reference, Capability, ToolCall, Payload,
)
from lang.labels import Label, LOW, integrity_at_least
from gate.monitor import Gate, GateError


H = '0011223344556677889900112233445566778899001122334455667788990011'
H2 = 'abcdef0000000000000000000000000000000000000000000000000000000000000'


class TestTokenizer(unittest.TestCase):
    def test_keywords(self):
        toks = tokenize("ASSERT QUERY DIRECT")
        self.assertEqual([t['value'] for t in toks if t['kind'] != 'EOF'],
                         ['ASSERT', 'QUERY', 'DIRECT'])

    def test_comment(self):
        toks = tokenize("ASSERT # comment\nQUERY")
        kinds = [t['kind'] for t in toks if t['kind'] != 'EOF']
        self.assertEqual(kinds, ['ACT', 'ACT'])

    def test_hash(self):
        toks = tokenize(f"cap:{H}")
        self.assertEqual(toks[2]['kind'], 'HASH')

    def test_short_hash(self):
        toks = tokenize("cap:00112233")
        self.assertEqual(toks[2]['kind'], 'HASH')


class TestParser(unittest.TestCase):
    def test_assert(self):
        acts = parse(f"ASSERT ev:(user:g, sha256:{H}) data:<opaque>")
        self.assertIsInstance(acts[0], AssertAct)
        self.assertEqual(acts[0].evidence.principal.id, 'user:g')
        self.assertEqual(acts[0].evidence.content_hash, H)
        self.assertTrue(acts[0].data.is_opaque)

    def test_query(self):
        acts = parse(f"QUERY  ev:(srv:abcdef00, sha256:{H2}) data:<opaque>")
        self.assertIsInstance(acts[0], QueryAct)

    def test_direct(self):
        src = f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        acts = parse(src)
        self.assertIsInstance(acts[0], DirectAct)
        self.assertEqual(acts[0].capability.scope, 'fs.read')
        self.assertEqual(acts[0].capability.exp, 60)
        self.assertEqual(acts[0].call.tool.principal.id, 'srv:abcdef00')
        self.assertEqual(acts[0].call.params['path'], '/logs')

    def test_commit(self):
        acts = parse(f"COMMIT (srv:abcdef00, sha256:{H2})")
        self.assertIsInstance(acts[0], CommitAct)

    def test_grant(self):
        acts = parse(f"GRANT  cap:{H} (scope=fs.read, exp=60, from=user:g)")
        self.assertIsInstance(acts[0], GrantAct)

    def test_revoke(self):
        acts = parse(f"REVOKE cap:{H} (scope=fs.read, exp=60, from=user:g)")
        self.assertIsInstance(acts[0], RevokeAct)

    def test_endorse(self):
        acts = parse(f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin")
        self.assertIsInstance(acts[0], EndorseAct)
        self.assertEqual(acts[0].signer.id, 'admin')

    def test_all_7_acts(self):
        src = f"""
ASSERT ev:(user:aabbccdd, sha256:{H}) data:<opaque, non-promotable>
QUERY  ev:(srv:abcdef00, sha256:{H2}) data:<opaque, some data>
DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: "/logs"}}
COMMIT (srv:abcdef00, sha256:{H2})
GRANT  cap:{H} (scope=fs.read, exp=60, from=user:g)
REVOKE cap:{H} (scope=fs.read, exp=60, from=user:g)
ENDORSE (srv:abcdef00, sha256:{H2}) by:admin
"""
        acts = parse(src)
        self.assertEqual(len(acts), 7)

    def test_invalid_syntax(self):
        with self.assertRaises(ParseError):
            parse("INVALID")

    def test_unterminated_opaque_payload_rejected(self):
        # Missing closing '>' must fail to parse.
        with self.assertRaises(ParseError):
            parse(f"ASSERT ev:(user:g, sha256:{H}) data:<opaque")

    def test_unterminated_string_payload_rejected(self):
        # Missing closing quote before EOF.
        with self.assertRaises(ParseError):
            parse('QUERY ev:(srv:abcdef00, sha256:' + H2 + ') data:"unterminated')

    def test_opening_delimiter_immediately_followed_by_eof(self):
        # '<' immediately followed by EOF must be rejected at tokenize time.
        with self.assertRaises(ParseError):
            tokenize("data:<")

    def test_empty_and_nonempty_payloads_tokenize(self):
        # Correctly closed empty/nonempty payloads remain tokenizable.
        for src in ('data:<>', 'data:""', 'data:<x>', 'data:"y"'):
            kinds = [t['kind'] for t in tokenize(src)]
            self.assertIn("OPAQUE" if "<" in src else "STRING", kinds, src)

    def test_valid_act_followed_by_unterminated_act_rejects_entire_program(self):
        # A valid act followed by an unterminated act must reject the program.
        src = (
            "COMMIT (user:g, sha256:" + H + ")\\n"
            "ASSERT ev:(user:g, sha256:" + H + ") data:<opaque"
        )
        with self.assertRaises(ParseError):
            parse(src)


class TestCapabilitySpecValidation(unittest.TestCase):
    """Regression tests: malformed capability spec fields must not silently
    become valid defaults. scope/exp/from are each required exactly once;
    unknown, duplicate, missing, malformed, and overflowing fields all reject.
    Keeps DIRECT, GRANT, and REVOKE under one strict grammar."""

    HASH = '0011223344556677889900112233445566778899001122334455667788990011'

    def _grant(self, spec: str) -> str:
        return f"GRANT cap:{self.HASH} ({spec})"

    def test_valid_cap_spec_accepted(self):
        parse(self._grant("scope=fs.read, exp=60, from=user:g"))

    def test_i64_max_ttl_accepted(self):
        # i64::MAX is a positive control at the upper bound.
        parse(self._grant("scope=fs.read, exp=9223372036854775807, from=user:g"))

    def test_quoted_number_exp_rejected(self):
        # exp="1_0" must not silently become 10.
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=\"10\", from=user:g"))

    def test_underscore_number_exp_rejected(self):
        # exp=1_0 must not silently become 10.
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=1_0, from=user:g"))

    def test_opaque_numeric_exp_rejected(self):
        # exp=<10> must not silently become 10.
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=<10>, from=user:g"))

    def test_missing_exp_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, from=user:g"))

    def test_misspelled_exp_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, expiry=60, from=user:g"))

    def test_missing_scope_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("exp=60, from=user:g"))

    def test_missing_from_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=60"))

    def test_unknown_key_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=60, from=user:g, extra=1"))

    def test_duplicate_key_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, scope=fs.write, exp=60, from=user:g"))

    def test_malformed_exp_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=oops, from=user:g"))

    def test_out_of_range_exp_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=-1, from=user:g"))

    def test_overflow_exp_rejected(self):
        with self.assertRaises(ParseError):
            parse(self._grant("scope=fs.read, exp=99999999999999999999, from=user:g"))

    def test_direct_rejects_malformed_spec(self):
        src = f"DIRECT cap:{self.HASH} (scope=fs.read, exp=oops, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        with self.assertRaises(ParseError):
            parse(src)

    def test_revoke_rejects_malformed_spec(self):
        with self.assertRaises(ParseError):
            parse(f"REVOKE cap:{self.HASH} (exp=60)")


class TestRequiredLiteralValidation(unittest.TestCase):
    """Regression tests: required syntax literals (ev, sha256, data, cap,
    call, tool) must match exactly. A wrong identifier value must be rejected
    even when the token kind is correct."""

    BASE = f"ASSERT ev:(user:g, sha256:{H}) data:<opaque>"
    DIRECT = f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"

    def _mutate(self, base: str, right: str, wrong: str) -> str:
        self.assertIn(right, base)
        return base.replace(right, wrong, 1)

    def test_ev_must_be_ev(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.BASE, 'ev', 'eV'))

    def test_sha256_must_be_sha256(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.BASE, 'sha256', 'sha512'))

    def test_data_must_be_data(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.BASE, 'data', 'payload'))

    def test_cap_must_be_cap(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.DIRECT, 'cap', 'capz'))

    def test_call_must_be_call(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.DIRECT, 'call', 'invoke'))

    def test_tool_must_be_tool(self):
        with self.assertRaises(ParseError):
            parse(self._mutate(self.DIRECT, 'tool', 'fn'))

    def test_correct_syntax_still_accepted(self):
        self.assertEqual(len(parse(self.BASE)), 1)
        self.assertEqual(len(parse(self.DIRECT)), 1)

    def test_malformed_later_act_rejects_whole_program(self):
        # Valid act followed by a malformed act rejects the program.
        src = (
            "COMMIT (user:g, sha256:" + H + ")\n"
            "ASSERT eV:(user:g, sha256:" + H + ") data:<opaque>"
        )
        with self.assertRaises(ParseError):
            parse(src)


class TestLabels(unittest.TestCase):
    def test_integrity_order(self):
        self.assertTrue(integrity_at_least('critical', 'high'))
        self.assertFalse(integrity_at_least('low', 'medium'))

    def test_join(self):
        joined = LOW.join(Label(integrity='high'))
        self.assertEqual(joined.integrity, 'low')

    def test_confidentiality(self):
        self.assertEqual(Label(confidentiality='public').confidentiality, 'public')


class TestGate(unittest.TestCase):
    def test_assert_allowed(self):
        g = Gate()
        acts = parse(f"ASSERT ev:(user:g, sha256:{H}) data:<opaque>")
        g.execute(acts[0])
        self.assertTrue(any(a['status'] == 'ALLOW' for a in g.audit))

    def test_direct_allowed(self):
        g = Gate()
        src = f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        acts = parse(src)
        g.execute(acts[0])

    def test_direct_cap_empty_scope_direct_ast(self):
        # Direct AST construction bypass: empty scope must be rejected at gate.
        g = Gate()
        cap = Capability(cap_hash=H, scope="", exp=60, from_principal=Principal("user:g", "0"*32))
        act = DirectAct(capability=cap, call=ToolCall(
            tool=Reference(principal=Principal("srv:abcdef00", "0"*32), content_hash=H2),
            params={}))
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_direct_cap_invalid_scope_seg_direct_ast(self):
        # Direct AST construction bypass: double-dot scope must be rejected.
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs..read", exp=60, from_principal=Principal("user:g", "0"*32))
        act = DirectAct(capability=cap, call=ToolCall(
            tool=Reference(principal=Principal("srv:abcdef00", "0"*32), content_hash=H2),
            params={}))
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_direct_cap_empty_from_direct_ast(self):
        # Direct AST construction bypass: empty issuer must be rejected.
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs.read", exp=60, from_principal=Principal("", "0"*32))
        act = DirectAct(capability=cap, call=ToolCall(
            tool=Reference(principal=Principal("srv:abcdef00", "0"*32), content_hash=H2),
            params={}))
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_direct_cap_invalid_from_seg_direct_ast(self):
        # Direct AST construction bypass: issuer segment with bad chars rejected.
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs.read", exp=60, from_principal=Principal("user:bad-name", "0"*32))
        act = DirectAct(capability=cap, call=ToolCall(
            tool=Reference(principal=Principal("srv:abcdef00", "0"*32), content_hash=H2),
            params={}))
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_grant_cap_empty_scope_direct_ast(self):
        g = Gate()
        cap = Capability(cap_hash=H, scope="", exp=60, from_principal=Principal("user:g", "0"*32))
        act = GrantAct(capability=cap)
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_grant_cap_empty_from_direct_ast(self):
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs.read", exp=60, from_principal=Principal("", "0"*32))
        act = GrantAct(capability=cap)
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_revoke_cap_empty_scope_direct_ast(self):
        g = Gate()
        cap = Capability(cap_hash=H, scope="", exp=60, from_principal=Principal("user:g", "0"*32))
        act = RevokeAct(capability=cap)
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_revoke_cap_empty_from_direct_ast(self):
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs.read", exp=60, from_principal=Principal("", "0"*32))
        act = RevokeAct(capability=cap)
        with self.assertRaises(GateError) as cm:
            g.execute(act)
        self.assertEqual(cm.exception.code, "CAPABILITY.INVALID")
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_direct_cap_valid_direct_ast(self):
        g = Gate()
        cap = Capability(cap_hash=H, scope="fs.read", exp=60, from_principal=Principal("user:g", "0"*32))
        act = DirectAct(capability=cap, call=ToolCall(
            tool=Reference(principal=Principal("srv:abcdef00", "0"*32), content_hash=H2),
            params={}))
        g.execute(act)

    def test_endorse_unauthorized(self):
        g = Gate()
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:user:unknown"
        acts = parse(src)
        with self.assertRaises(GateError):
            g.execute(acts[0])

    def test_endorse_authorized(self):
        g = Gate()
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin"
        acts = parse(src)
        g.execute(acts[0])

    def test_scan(self):
        g = Gate()
        src = f"ASSERT ev:(user:g, sha256:{H}) data:<opaque>"
        ok, audit = g.scan(src)
        self.assertTrue(ok)


class TestGateAuthorization(unittest.TestCase):
    """Regression tests for the empty-policy authorization bug.

    An explicitly empty signer_authority dict must NOT fall through to the
    built-in admin/reviewer defaults; only None retains those defaults.
    """

    def test_empty_dict_denies_all(self):
        """Gate(signer_authority={}) must reject every endorsement."""
        g = Gate(signer_authority={})
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin"
        acts = parse(src)
        with self.assertRaises(GateError) as ctx:
            g.execute(acts[0])
        self.assertEqual(ctx.exception.code, 'ENDORSE.UNAUTHORIZED')

    def test_explicit_empty_allowlist_denies_all(self):
        """Gate(signer_authority={'may_approve_integrity': []}) must reject every endorsement."""
        g = Gate(signer_authority={'may_approve_integrity': []})
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin"
        acts = parse(src)
        with self.assertRaises(GateError) as ctx:
            g.execute(acts[0])
        self.assertEqual(ctx.exception.code, 'ENDORSE.UNAUTHORIZED')

    def test_none_retains_default_admin(self):
        """Gate(signer_authority=None) must allow the default admin signer."""
        g = Gate(signer_authority=None)
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin"
        acts = parse(src)
        g.execute(acts[0])  # should not raise

    def test_none_retains_default_reviewer(self):
        """Gate(signer_authority=None) must allow the default reviewer:top signer."""
        g = Gate(signer_authority=None)
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:reviewer:top"
        acts = parse(src)
        g.execute(acts[0])

    def test_populated_policy_allows_intended_signer(self):
        """Explicit populated policy allows its listed signer."""
        g = Gate(signer_authority={'may_approve_integrity': [('custom', 'any')]})
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:custom:anything"
        acts = parse(src)
        g.execute(acts[0])

    def test_populated_policy_denies_non_listed_signer(self):
        """Explicit populated policy denies a non-listed signer."""
        g = Gate(signer_authority={'may_approve_integrity': [('custom', 'any')]})
        src = f"ENDORSE (srv:abcdef00, sha256:{H2}) by:admin"
        acts = parse(src)
        with self.assertRaises(GateError) as ctx:
            g.execute(acts[0])
        self.assertEqual(ctx.exception.code, 'ENDORSE.UNAUTHORIZED')


class TestGateUnsupportedActs(unittest.TestCase):
    """Regression tests: unsupported act types must be rejected, not silently allowed."""

    def test_plain_act_rejected(self):
        """A plain Act() must raise ACT.UNSUPPORTED and its audit entry ends in DENY."""
        from lang.ast import Act
        g = Gate()
        act = Act()
        with self.assertRaises(GateError) as ctx:
            g.execute(act)
        self.assertEqual(ctx.exception.code, 'ACT.UNSUPPORTED')
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_unknown_act_subclass_rejected(self):
        """An unknown Act subclass must raise ACT.UNSUPPORTED."""
        from lang.ast import Act
        class WeirdAct(Act):
            act_type = 'WEIRD'
        g = Gate()
        act = WeirdAct()
        with self.assertRaises(GateError) as ctx:
            g.execute(act)
        self.assertEqual(ctx.exception.code, 'ACT.UNSUPPORTED')
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')

    def test_unknown_subclass_with_direct_act_type_rejected(self):
        """An unknown subclass with act_type='DIRECT' must still be rejected (dispatch by type, not string)."""
        from lang.ast import Act
        class FakeDirect(Act):
            act_type = 'DIRECT'
        g = Gate()
        act = FakeDirect()
        with self.assertRaises(GateError) as ctx:
            g.execute(act)
        self.assertEqual(ctx.exception.code, 'ACT.UNSUPPORTED')
        self.assertEqual(len(g.audit), 1)
        self.assertEqual(g.audit[0]['status'], 'DENY')


class TestParamValues(unittest.TestCase):
    """Regression tests for the parameter-value grammar/type contract.

    Python used to silently drop HASH and OPAQUE values while allowing the
    directive; the contract is now: STRING/IDENT -> str, NUMBER/decimal-only
    HASH -> int (0..=i64::MAX), everything else rejected. Rust mirrors this.
    """

    def _direct(self, params_src: str) -> DirectAct:
        return parse(
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{{params_src}}}"
        )[0]

    def test_number_value_is_int(self):
        act = self._direct('count: 123')
        self.assertEqual(act.call.params['count'], 123)
        self.assertIsInstance(act.call.params['count'], int)

    def test_canonical_encoding_unambiguous_for_multiline(self):
        # Regression: canonical encoding must escape backslashes and newlines inside
        # string values so a single multiline string never collides with separate
        # key=value lines (e.g. {a: "x\nP b i:1"} vs {a: "x", b: 1}).
        import types

        def canon(params: dict) -> str:
            act = types.SimpleNamespace(call=types.SimpleNamespace(params=params))
            return canonical_params(act)

        from conformance import diff_fuzz as _df
        _df_canonical = _df.canonical_params

        # Case 1: one string containing an escaped-looking newline
        a = _df_canonical(types.SimpleNamespace(call=types.SimpleNamespace(params={'a': 'x\nP b i:1'})))
        # Case 2: two separate arguments
        b = _df_canonical(types.SimpleNamespace(call=types.SimpleNamespace(params={'a': 'x', 'b': 1})))
        self.assertNotEqual(a, b)

    def test_decimal_hash_value_is_int(self):
        # Decimal sequences of 8+ digits tokenize as HASH; they must not be dropped.
        act = self._direct('count: 12345678')
        self.assertEqual(act.call.params['count'], 12345678)
        self.assertIsInstance(act.call.params['count'], int)

    def test_ident_value_is_str(self):
        act = self._direct('count: myid')
        self.assertEqual(act.call.params['count'], 'myid')
        self.assertIsInstance(act.call.params['count'], str)

    def test_string_value_is_str(self):
        act = self._direct('path: "/logs"')
        self.assertEqual(act.call.params['path'], '/logs')
        self.assertIsInstance(act.call.params['path'], str)

    def test_multiple_params_preserved(self):
        act = self._direct('count: 12345678, extra: 456')
        self.assertEqual(act.call.params['count'], 12345678)
        self.assertEqual(act.call.params['extra'], 456)

    def test_opaque_value_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('data: <opaque>')

    def test_nondecimal_hash_value_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('digest: abcdef12')

    def test_out_of_range_number_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('count: 9223372036854775808')

    def test_i64_max_accepted(self):
        act = self._direct('count: 9223372036854775807')
        self.assertEqual(act.call.params['count'], 9223372036854775807)
        self.assertIsInstance(act.call.params['count'], int)

    def test_duplicate_param_key_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('path: "first", path: "second"')

    def test_duplicate_param_key_same_value_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('count: 1, count: 1')

    def test_duplicate_param_key_different_type_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('count: 1, count: "one"')

    def test_missing_comma_rejected(self):
        with self.assertRaises(ParseError):
            self._direct('path: "/logs" count: 1')

    def test_empty_params_accepted(self):
        act = self._direct('')
        self.assertEqual(act.call.params, {})

    def test_valid_multi_param_with_commas_accepted(self):
        act = self._direct('count: 12345678, extra: 456')
        self.assertEqual(act.call.params['count'], 12345678)
        self.assertEqual(act.call.params['extra'], 456)

    def test_malformed_later_act_rejects_whole_program(self):
        src = (
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}\n"
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{count: 1, count: 2}}"
        )
        with self.assertRaises(ParseError):
            parse(src)

    def test_leading_zeros_ttl_parses_as_one(self):
        # Thousands of leading zeros followed by 1 must parse as TTL=1,
        # matching Rust's i64 parse which accepts leading zeros.
        zeros = '0' * 5000
        act = self._direct(f'count: 1')  # just to have a DIRECT shell
        src = (
            f"DIRECT cap:{H} (scope=fs.read, exp={zeros}1, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        )
        acts = parse(src)
        self.assertEqual(len(acts), 1)

    def test_leading_zeros_param_parses_as_one(self):
        zeros = '0' * 5000
        act = self._direct(f'count: {zeros}1')
        self.assertEqual(act.call.params['count'], 1)

    def test_all_zeros_ttl_parses_as_zero(self):
        zeros = '0' * 1000
        src = (
            f"DIRECT cap:{H} (scope=fs.read, exp={zeros}, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        )
        acts = parse(src)
        self.assertEqual(len(acts), 1)

    def test_all_zeros_param_parses_as_zero(self):
        act = self._direct('count: 0000')
        self.assertEqual(act.call.params['count'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
