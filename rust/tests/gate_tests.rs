//! Rust test suite for L: A Trust-Typed Language for Agents.

#[cfg(test)]
mod structural_boundary {
    use tsd_rust::ast::*;
    use tsd_rust::gate::Gate;

    fn capability() -> Capability {
        Capability { cap_hash: "a".repeat(64), scope: "fs.read".into(), exp: 60,
            from_principal: Principal { id: "user:g".into(), hash: String::new() },
            integrity_level: "low".into() }
    }

    fn reference_acts(reference: Reference) -> Vec<Act> {
        let payload = Payload { content: "x".into(), is_opaque: true };
        vec![
            Act::Assert(AssertAct { evidence: reference.clone(), data: payload.clone() }),
            Act::Query(QueryAct { evidence: reference.clone(), data: payload }),
            Act::Commit(CommitAct { reference: reference.clone() }),
            Act::Endorse(EndorseAct { reference: reference.clone(),
                signer: Principal { id: "admin".into(), hash: String::new() } }),
            Act::Direct(DirectAct { capability: capability(),
                call: ToolCall { tool: reference, params: Default::default() } }),
        ]
    }

    #[test]
    fn i4_i7_empty_reference_fields_deny_all_reference_acts() {
        for (id, hash) in [("", "aaaaaaaa"), ("srv:x", "")] {
            let reference = Reference {
                principal: Principal { id: id.into(), hash: String::new() },
                content_hash: hash.into(),
            };
            for act in reference_acts(reference) {
                let mut gate = Gate::new();
                let error = gate.execute(&act, Some(0)).expect_err("invalid reference allowed");
                assert_eq!(error.code(), "REFERENCE.INVALID");
                assert_eq!(gate.audit[0].2, "DENY");
            }
        }
    }

    #[test]
    fn i4_i7_valid_reference_controls() {
        let reference = Reference { principal: Principal { id: "srv:x".into(),
            hash: String::new() }, content_hash: "a".repeat(64) };
        for act in reference_acts(reference) {
            let mut gate = Gate::new();
            gate.execute(&act, Some(0)).expect("valid reference rejected");
            assert_eq!(gate.audit[0].2, "ALLOW");
        }
    }

    #[test]
    fn i4_i7_empty_signer_is_invalid_reference() {
        let act = Act::Endorse(EndorseAct {
            reference: Reference { principal: Principal { id: "srv:x".into(),
                hash: String::new() }, content_hash: "a".repeat(64) },
            signer: Principal { id: String::new(), hash: String::new() },
        });
        let mut gate = Gate::new();
        assert_eq!(gate.execute(&act, Some(0)).unwrap_err().code(), "REFERENCE.INVALID");
        assert_eq!(gate.audit[0].2, "DENY");
    }

    #[test]
    fn i7_capability_hash_error_precedes_scope_error() {
        let mut cap = capability();
        cap.cap_hash.clear();
        cap.scope.clear();
        for act in [Act::Grant(GrantAct { capability: cap.clone() }),
                    Act::Revoke(RevokeAct { capability: cap })] {
            let mut gate = Gate::new();
            assert_eq!(gate.execute(&act, Some(0)).unwrap_err().code(), "REFERENCE.INVALID");
            assert_eq!(gate.audit[0].2, "DENY");
        }
    }

    #[test]
    fn i6_audit_retains_only_newest_records() {
        use tsd_rust::limits::MAX_AUDIT_RECORDS;
        let mut gate = Gate::default();
        let act = Act::Commit(CommitAct { reference: Reference {
            principal: Principal { id: "srv:x".into(), hash: String::new() },
            content_hash: "a".repeat(64),
        } });
        for now in 0..MAX_AUDIT_RECORDS + 3 {
            gate.execute(&act, Some(now as u64)).unwrap();
        }
        assert_eq!(gate.audit.len(), MAX_AUDIT_RECORDS);
        assert_eq!(gate.audit[0].1, 3);
    }
}

#[cfg(test)]
mod tests {
    use tsd_rust::ast::*;
    use tsd_rust::parser::*;
    use tsd_rust::gate::*;

    fn assert_ok(src: &str) -> Vec<Act> {
        let acts = parse(src).expect("parse should succeed");
        assert!(!acts.is_empty(), "parsed acts should be non-empty");
        acts
    }

    #[test]
    fn test_tokenizer_keyword() {
        let toks = tokenize("ASSERT QUERY DIRECT").unwrap();
        let kinds: Vec<_> = toks.iter().map(|t| t.kind.clone()).collect();
        assert_eq!(kinds, vec![Kind::ACT, Kind::ACT, Kind::ACT, Kind::EOF]);
    }

    #[test]
    fn test_tokenizer_comment() {
        let toks = tokenize("ASSERT # comment\nQUERY").unwrap();
        let kinds: Vec<_> = toks.iter().map(|t| t.kind.clone()).collect();
        assert_eq!(kinds, vec![Kind::ACT, Kind::ACT, Kind::EOF]);
    }

    #[test]
    fn test_tokenizer_hash() {
        let toks = tokenize("cap:00112233").unwrap();
        assert_eq!(toks[0].kind, Kind::IDENT);
        assert_eq!(toks[1].kind, Kind::COLON);
        assert_eq!(toks[2].kind, Kind::HASH);
    }

    #[test]
    fn test_tokenizer_short_hash() {
        let toks = tokenize("cap:0011223344556677889900112233445566778899001122334455667788990011").unwrap();
        assert_eq!(toks[2].kind, Kind::HASH);
    }

    #[test]
    fn test_assert_act() {
        let acts = assert_ok("ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque, non-promotable>");
        match &acts[0] {
            Act::Assert(a) => {
                assert_eq!(a.evidence.principal.id, "user:g");
                assert_eq!(a.evidence.content_hash.len(), 64);
                assert!(a.data.is_opaque);
            }
            _ => panic!("expected Assert act"),
        }
    }

    #[test]
    fn test_query_act() {
        let acts = assert_ok("QUERY  ev:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) data:<opaque, some data>");
        match &acts[0] {
            Act::Query(a) => {
                assert_eq!(a.evidence.principal.id, "srv:abcdef00");
                assert!(a.data.is_opaque);
            }
            _ => panic!("expected Query act"),
        }
    }

    #[test]
    fn test_direct_act() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\"}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.capability.scope, "fs.read");
                assert_eq!(d.capability.exp, 60);
                assert_eq!(d.capability.from_principal.id, "user:g");
                assert_eq!(d.call.tool.principal.id, "srv:abcdef00");
                assert_eq!(d.call.params.get("path"), Some(&ParamValue::Str("/logs".to_string())));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_commit_act() {
        let acts = assert_ok("COMMIT (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000)");
        match &acts[0] {
            Act::Commit(c) => {
                assert_eq!(c.reference.principal.id, "srv:abcdef00");
            }
            _ => panic!("expected Commit act"),
        }
    }

    #[test]
    fn test_grant_act() {
        let acts = assert_ok("GRANT  cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g)");
        match &acts[0] {
            Act::Grant(g) => {
                assert_eq!(g.capability.scope, "fs.read");
            }
            _ => panic!("expected Grant act"),
        }
    }

    #[test]
    fn test_revoke_act() {
        let acts = assert_ok("REVOKE cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g)");
        match &acts[0] {
            Act::Revoke(r) => {
                assert_eq!(r.capability.scope, "fs.read");
            }
            _ => panic!("expected Revoke act"),
        }
    }

    #[test]
    fn test_endorse_act() {
        let acts = assert_ok("ENDORSE (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) by:admin");
        match &acts[0] {
            Act::Endorse(e) => {
                assert_eq!(e.signer.id, "admin");
            }
            _ => panic!("expected Endorse act"),
        }
    }

    #[test]
    fn test_all_7_acts() {
        let src = "
ASSERT ev:(user:aabbccdd, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque, non-promotable>
QUERY  ev:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) data:<opaque, some data>
DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\"}
COMMIT (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000)
GRANT  cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g)
REVOKE cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g)
ENDORSE (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) by:admin
";
        let acts = assert_ok(src);
        assert_eq!(acts.len(), 7, "should parse all 7 acts");
    }

    #[test]
    fn test_invalid_syntax() {
        let result = parse("INVALID");
        assert!(result.is_err(), "invalid input should produce ParseError");
    }


    #[test]
    fn test_tokenizer_unterminated_opaque() {
        // Missing closing '>' must fail to tokenize.
        let r = tokenize(r#"ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque"#);
        assert!(r.is_err(), "unterminated opaque payload must be rejected");
        let e = r.unwrap_err();
        assert_eq!(e.msg, "unterminated opaque payload");
    }

    #[test]
    fn test_tokenizer_unterminated_string() {
        // No closing quote before EOF.
        let r = tokenize(r##"ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:"unterminated"##);
        assert!(r.is_err(), "unterminated string must be rejected");
        let e = r.unwrap_err();
        assert_eq!(e.msg, "unterminated string");
    }

    #[test]
    fn test_tokenizer_unterminated_at_eof() {
        // Opening delimiter immediately followed by EOF.
        assert!(tokenize("data:<").is_err(), "bare '<' at EOF must be rejected");
        assert!(tokenize("data:").is_ok(), "data: alone is valid (no payload yet)");
    }

    #[test]
    fn test_tokenizer_empty_payloads_still_valid() {
        // Correctly closed empty and nonempty payloads remain valid.
        assert!(tokenize("data:<>").is_ok(), "empty opaque payload accepted");
        assert!(tokenize("data:\"\"").is_ok(), "empty string payload accepted");
        assert!(tokenize("data:<x>").is_ok(), "nonempty opaque payload accepted");
        assert!(tokenize("data:\"y\"").is_ok(), "nonempty string payload accepted");
    }

    #[test]
    fn test_unterminated_rejects_whole_program() {
        // A valid act followed by an unterminated act must reject the program.
        let src = "COMMIT (user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011)\nASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque";
        let r = parse(src);
        assert!(r.is_err(), "unterminated act in a multi-act program must be rejected");
    }

    #[test]
    fn test_required_literals_ev_sha256_data_cap_call_tool() {
        // Every required literal must match exactly; a wrong identifier value
        // is rejected even when the token kind is correct.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        let h2 = "abcdef0000000000000000000000000000000000000000000000000000000000000";
        let correct_assert = format!("ASSERT ev:(user:g, sha256:{}) data:<opaque>", h);
        let correct_direct = format!("DIRECT cap:{} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{}) {{path: \"/logs\"}}", h, h2);
        let bad_ev = correct_assert.replace("ev", "eV");
        let bad_sha = correct_assert.replace("sha256", "sha512");
        let bad_data = correct_assert.replace("data", "payload");
        let bad_cap = correct_direct.replace("cap", "capz");
        let bad_call = correct_direct.replace("call", "invoke");
        let bad_tool = correct_direct.replace("tool", "fn");
        assert!(parse(&bad_ev).is_err(), "mut ev must be rejected");
        assert!(parse(&bad_sha).is_err(), "mut sha256 must be rejected");
        assert!(parse(&bad_data).is_err(), "mut data must be rejected");
        assert!(parse(&bad_cap).is_err(), "mut cap must be rejected");
        assert!(parse(&bad_call).is_err(), "mut call must be rejected");
        assert!(parse(&bad_tool).is_err(), "mut tool must be rejected");
        assert!(parse(&correct_assert).is_ok(), "correct assert accepted");
        assert!(parse(&correct_direct).is_ok(), "correct direct accepted");
    }

    #[test]
    fn test_malformed_later_act_rejects_whole_program() {
        // A valid act followed by a malformed act rejects the whole program.
        let src = "COMMIT (user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011)\nASSERT eV:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque>";
        let r = parse(src);
        assert!(r.is_err(), "malformed act in multi-act program must be rejected");
    }

    #[test]
    fn test_cap_spec_valid_controls() {
        // Valid controls for DIRECT, GRANT, REVOKE with strict grammar.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        let h2 = "abcdef0000000000000000000000000000000000000000000000000000000000000";
        assert!(parse(&format!("GRANT  cap:{} (scope=fs.read, exp=60, from=user:g)", h)).is_ok());
        assert!(parse(&format!("REVOKE cap:{} (scope=fs.read, exp=60, from=user:g)", h)).is_ok());
        assert!(parse(&format!("DIRECT cap:{} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{}) {{path: \"/logs\"}}", h, h2)).is_ok());
    }

    #[test]
    fn test_cap_spec_missing_fields_rejected() {
        // Missing scope, exp, or from must reject.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        assert!(parse(&format!("GRANT cap:{} (exp=60, from=user:g)", h)).is_err());
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, from=user:g)", h)).is_err());
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=60)", h)).is_err());
    }

    #[test]
    fn test_cap_spec_unknown_and_duplicate_keys_rejected() {
        // Unknown and duplicate capability keys must reject.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=60, from=user:g, extra=1)", h)).is_err());
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, scope=fs.write, exp=60, from=user:g)", h)).is_err());
    }

    #[test]
    fn test_cap_spec_malformed_and_out_of_range_exp_rejected() {
        // Malformed, negative, and overflow exp must reject consistently.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=oops, from=user:g)", h)).is_err());
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=-1, from=user:g)", h)).is_err());
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=99999999999999999999, from=user:g)", h)).is_err());
    }

    #[test]
    fn test_cap_spec_misspelled_key_rejected() {
        // Misspelled expiry must not silently become the default 60.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, expiry=60, from=user:g)", h)).is_err());
    }

    #[test]
    fn test_cap_spec_numeric_format_lexical_validation() {
        // Numeric-format lexical validation must be consistent with Python:
        // unquoted ASCII-decimal required; i64::MAX is the upper-bound positive control.
        let h = "0011223344556677889900112233445566778899001122334455667788990011";
        // Underscore must be rejected.
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=1_0, from=user:g)", h)).is_err());
        // Quoted number must be rejected.
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=\"10\", from=user:g)", h)).is_err());
        // Opaque numeric payload must be rejected.
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=<10>, from=user:g)", h)).is_err());
        // i64::MAX upper bound accepted (positive control).
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=9223372036854775807, from=user:g)", h)).is_ok());
        // Overflow above i64::MAX rejected.
        assert!(parse(&format!("GRANT cap:{} (scope=fs.read, exp=9223372036854775808, from=user:g)", h)).is_err());
    }

    #[test]
    fn test_gate_allow_assert() {
        let src = "ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque>";
        let acts = assert_ok(src);
        let mut gate = Gate::new();
        assert!(gate.execute(&acts[0], None).is_ok());
    }

    #[test]
    fn test_gate_allow_direct() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\"}";
        let acts = assert_ok(src);
        let mut gate = Gate::new();
        assert!(gate.execute(&acts[0], None).is_ok());
    }

    #[test]
    fn test_gate_deny_endorse_unauthorized() {
        let src = "ENDORSE (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) by:user:unknown";
        let acts = assert_ok(src);
        let mut gate = Gate::new();
        let err = gate.execute(&acts[0], None).unwrap_err();
        assert!(err.to_string().starts_with("ENDORSE.UNAUTHORIZED"));
    }

    #[test]
    fn test_gate_allow_endorse_authorized() {
        let src = "ENDORSE (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) by:admin";
        let acts = assert_ok(src);
        let mut gate = Gate::new();
        assert!(gate.execute(&acts[0], None).is_ok());
    }

    #[test]
    fn test_gate_scan() {
        let src = "
ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque>
COMMIT (srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000)
";
        let mut gate = Gate::new();
        let (all_allowed, audit) = gate.scan(src).expect("scan should succeed");
        assert!(all_allowed);
        assert_eq!(audit.len(), 2);
    }

    #[test]
    fn test_gate_deny_negative_ttl() {
        let src = "GRANT  cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=0, from=user:g)";
        let acts = assert_ok(src);
        let mut gate = Gate::new();
        assert!(gate.execute(&acts[0], None).is_err());
    }

    fn make_cap(scope: &str, from: &str) -> Capability {
        Capability {
            cap_hash: "0011223344556677889900112233445566778899001122334455667788990011".to_string(),
            scope: scope.to_string(),
            exp: 60,
            from_principal: Principal {
                id: from.to_string(),
                hash: "00".repeat(32),
            },
            integrity_level: "low".to_string(),
        }
    }

    fn make_direct_act(cap: Capability) -> Act {
        Act::Direct(DirectAct {
            capability: cap,
            call: ToolCall {
                tool: Reference {
                    principal: Principal {
                        id: "srv:abcdef00".to_string(),
                        hash: "abcdef0000000000000000000000000000000000000000000000000000000000000".to_string(),
                    },
                    content_hash: "abcdef0000000000000000000000000000000000000000000000000000000000000".to_string(),
                },
                params: std::collections::HashMap::new(),
            },
        })
    }

    fn assert_capability_invalid_and_deny(gate: &mut Gate, act: &Act) {
        let err = gate.execute(act, None).unwrap_err();
        assert_eq!(err.code(), "CAPABILITY.INVALID", "expected CAPABILITY.INVALID, got {:?}", err);
        let audit = &gate.audit;
        assert!(!audit.is_empty(), "audit log should not be empty");
        let last = audit.last().unwrap();
        assert_eq!(last.2, "DENY", "audit status should be DENY, got {:?}", last.2);
    }

    #[test]
    fn test_gate_deny_direct_cap_empty_scope_direct_ast() {
        let cap = make_cap("", "user:g");
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_direct_cap_invalid_scope_seg_direct_ast() {
        let cap = make_cap("fs..read", "user:g");
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_direct_cap_empty_from_direct_ast() {
        let cap = make_cap("fs.read", "");
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_direct_cap_invalid_from_seg_direct_ast() {
        let cap = make_cap("fs.read", "user:bad-name");
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_grant_cap_empty_scope_direct_ast() {
        let cap = make_cap("", "user:g");
        let act = Act::Grant(GrantAct { capability: cap });
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_grant_cap_empty_from_direct_ast() {
        let cap = make_cap("fs.read", "");
        let act = Act::Grant(GrantAct { capability: cap });
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_revoke_cap_empty_scope_direct_ast() {
        let cap = make_cap("", "user:g");
        let act = Act::Revoke(RevokeAct { capability: cap });
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_revoke_cap_empty_from_direct_ast() {
        let cap = make_cap("fs.read", "");
        let act = Act::Revoke(RevokeAct { capability: cap });
        let mut gate = Gate::new();
        assert_capability_invalid_and_deny(&mut gate, &act);
    }

    #[test]
    fn test_gate_deny_direct_ttl_zero_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 0;
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        let err = gate.execute(&act, None).unwrap_err();
        assert_eq!(err.code(), "EXPIRY.INVALID", "expected EXPIRY.INVALID, got {:?}", err);
        let audit = &gate.audit;
        assert!(!audit.is_empty());
        let last = audit.last().unwrap();
        assert_eq!(last.2, "DENY", "audit status should be DENY, got {:?}", last.2);
    }

    #[test]
    fn test_gate_deny_direct_ttl_negative_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = -1;
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        let err = gate.execute(&act, None).unwrap_err();
        assert_eq!(err.code(), "EXPIRY.INVALID", "expected EXPIRY.INVALID, got {:?}", err);
        let audit = &gate.audit;
        assert!(!audit.is_empty());
        let last = audit.last().unwrap();
        assert_eq!(last.2, "DENY", "audit status should be DENY, got {:?}", last.2);
    }

    #[test]
    fn test_gate_deny_grant_ttl_zero_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 0;
        let act = Act::Grant(GrantAct { capability: cap });
        let mut gate = Gate::new();
        let err = gate.execute(&act, None).unwrap_err();
        assert_eq!(err.code(), "EXPIRY.INVALID", "expected EXPIRY.INVALID, got {:?}", err);
    }

    #[test]
    fn test_gate_deny_revoke_ttl_zero_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 0;
        let act = Act::Revoke(RevokeAct { capability: cap });
        let mut gate = Gate::new();
        let err = gate.execute(&act, None).unwrap_err();
        assert_eq!(err.code(), "EXPIRY.INVALID", "expected EXPIRY.INVALID, got {:?}", err);
    }

    #[test]
    fn test_gate_allow_direct_ttl_i64_max_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 9223372036854775807i64;
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_grant_ttl_i64_max_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 9223372036854775807i64;
        let act = Act::Grant(GrantAct { capability: cap });
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_revoke_ttl_i64_max_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 9223372036854775807i64;
        let act = Act::Revoke(RevokeAct { capability: cap });
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_direct_ttl_one_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 1;
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_grant_ttl_one_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 1;
        let act = Act::Grant(GrantAct { capability: cap });
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_revoke_ttl_one_direct_ast() {
        let mut cap = make_cap("fs.read", "user:g");
        cap.exp = 1;
        let act = Act::Revoke(RevokeAct { capability: cap });
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_gate_allow_direct_cap_valid_direct_ast() {
        let cap = make_cap("fs.read", "user:g");
        let act = make_direct_act(cap);
        let mut gate = Gate::new();
        assert!(gate.execute(&act, None).is_ok());
    }

    #[test]
    fn test_param_decimal_hash_value_preserved() {
        // Decimal sequences of 8+ digits tokenize as HASH but must parse as integers,
        // matching Python. Silently dropping them would lose a tool argument.
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 12345678}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(12345678)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_number_value_is_int() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 123}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(123)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_ident_value_is_str() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: myid}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Str("myid".to_string())));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_string_value_is_str() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\"}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("path"), Some(&ParamValue::Str("/logs".to_string())));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_opaque_value_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {data: <opaque>}";
        assert!(parse(src).is_err(), "opaque values in params must be rejected, not silently dropped");
    }

    #[test]
    fn test_param_nondecimal_hash_value_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {digest: abcdef12}";
        assert!(parse(src).is_err(), "non-decimal HASH values in params must be rejected");
    }

    #[test]
    fn test_param_out_of_range_number_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 9223372036854775808}";
        assert!(parse(src).is_err(), "numbers above i64::MAX must be rejected");
    }

    #[test]
    fn test_param_i64_max_accepted() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 9223372036854775807}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(9223372036854775807)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_duplicate_key_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"first\", path: \"second\"}";
        assert!(parse(src).is_err(), "duplicate param key must be rejected");
    }

    #[test]
    fn test_param_duplicate_key_same_value_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 1, count: 1}";
        assert!(parse(src).is_err(), "duplicate param key with same value must be rejected");
    }

    #[test]
    fn test_param_duplicate_key_different_type_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 1, count: \"one\"}";
        assert!(parse(src).is_err(), "duplicate param key with different type must be rejected");
    }

    #[test]
    fn test_param_missing_comma_rejected() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\" count: 1}";
        assert!(parse(src).is_err(), "missing comma between params must be rejected");
    }

    #[test]
    fn test_param_empty_map_accepted() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert!(d.call.params.is_empty());
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_valid_multi_param_with_commas_accepted() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {count: 12345678, extra: 456}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(12345678)));
                assert_eq!(d.call.params.get("extra"), Some(&ParamValue::Int(456)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_malformed_later_act_rejects_whole_program() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef0000000000000000000000000000000000000000000000000000000000000) {path: \"/logs\"}\nDIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef00000000000000000000000000000000000000000000000000000000000000) {count: 1, count: 2}";
        assert!(parse(src).is_err(), "malformed later act must reject whole program");
    }

    #[test]
    fn test_param_leading_zeros_parses_as_one() {
        let zeros = "0".repeat(5000);
        let src = format!(
            "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef00000000000000000000000000000000000000000000000000000000000000) {{count: {zeros}1}}"
        );
        let acts = assert_ok(&src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(1)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_param_all_zeros_parses_as_zero() {
        let src = "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:abcdef00000000000000000000000000000000000000000000000000000000000000) {count: 0000}";
        let acts = assert_ok(src);
        match &acts[0] {
            Act::Direct(d) => {
                assert_eq!(d.call.params.get("count"), Some(&ParamValue::Int(0)));
            }
            _ => panic!("expected Direct act"),
        }
    }

    #[test]
    fn test_ttl_leading_zeros_parses_as_one() {
        let zeros = "0".repeat(5000);
        let src = format!(
            "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp={zeros}1, from=user:g) call tool:(srv:abcdef00, sha256:abcdef00000000000000000000000000000000000000000000000000000000000000) {{path: \"/logs\"}}"
        );
        let acts = assert_ok(&src);
        assert_eq!(acts.len(), 1);
    }

    #[test]
    fn test_ttl_all_zeros_parses_as_zero() {
        let zeros = "0".repeat(1000);
        let src = format!(
            "DIRECT cap:0011223344556677889900112233445566778899001122334455667788990011 (scope=fs.read, exp={zeros}, from=user:g) call tool:(srv:abcdef00, sha256:abcdef00000000000000000000000000000000000000000000000000000000000000) {{path: \"/logs\"}}"
        );
        let acts = assert_ok(&src);
        assert_eq!(acts.len(), 1);
    }
}
