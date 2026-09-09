//! Logos-free helpers: the prompt a human reads, and argument normalisation.

use serde_json::{json, Value};

/// A request this module has claimed for display. `claim_lines` and `render_lines`
/// are the keystore's two lists and are never merged.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rendered {
    pub handle: String,
    pub bundle_id: String,
    pub requester: String,
    pub claim_lines: Vec<String>,
    pub render_lines: Vec<String>,
}

const RULE: &str = "================================================================";
const THIN: &str = "----------------------------------------------------------------";

/// The block `logosctl watch` prints. Starts with a newline so it left-aligns under the
/// `argN:` label; ends with the two commands to type.
pub fn render(r: &Rendered) -> String {
    let mut out = vec![
        String::new(),
        RULE.into(),
        format!("SIGNING REQUEST  {}", r.handle),
        format!("Requested by: {}", r.requester),
        THIN.into(),
        "Requester's claim (NOT verified by the keystore):".into(),
    ];
    if r.claim_lines.is_empty() {
        out.push("  (the requester made no claim)".into());
    } else {
        out.extend(r.claim_lines.iter().map(|l| format!("  {l}")));
    }
    out.push(THIN.into());
    out.push("What will be signed (the keystore's own words):".into());
    out.extend(r.render_lines.iter().map(|l| format!("  {l}")));
    out.push(THIN.into());
    out.push(format!(
        "approve:  logosctl call evm_signer_cli approve {} {} @/path/to/pwfile",
        r.handle, r.bundle_id
    ));
    out.push(format!("reject:   logosctl call evm_signer_cli reject {}", r.handle));
    out.push(RULE.into());
    out.join("\n")
}

/// Drop exactly one trailing newline: `@file` hands over the file verbatim, and a
/// password file written with `echo` ends in one.
pub fn strip_file_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// The form `approval.rs::approve` compares: trimmed, no `0x`, lowercase.
pub fn normalise_bundle_id(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_ascii_lowercase()
}

/// The exact `configure` command that adds `me` to `role` while keeping every name
/// already in force — `configure` is total, so a hint naming only `me` would strip
/// the GUI surfaces.
pub fn configure_hint(identity: &Value, me: &str, role: &str) -> String {
    let list = |key: &str| -> Vec<String> {
        identity
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let mut approvers = list("approvers");
    let mut custodians = list("custodians");
    let target = if role == "approvers" { &mut approvers } else { &mut custodians };
    if !target.iter().any(|n| n == me) {
        target.push(me.to_string());
    }
    let doc = json!({ "approvers": approvers, "custodians": custodians });
    format!("logosctl call keystore_module configure '{doc}'")
}

pub fn holds(identity: &Value, me: &str, role: &str) -> bool {
    identity
        .get(role)
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some(me)))
        .unwrap_or(false)
}

/// Best-effort: overwrite the bytes before the allocation is returned.
pub fn scrub(s: &mut String) {
    unsafe { s.as_mut_vec().fill(0) };
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Rendered {
        Rendered {
            handle: "ksh_abc".into(),
            bundle_id: "8c1e".into(),
            requester: "eth_wallet_backend".into(),
            claim_lines: vec!["Purpose (claimed by the requester): Send 1 ETH".into()],
            render_lines: vec!["Account: 0xf39F".into(), "Commitment: 8c1e".into()],
        }
    }

    #[test]
    fn render_keeps_the_two_lists_apart_and_verbatim() {
        let text = render(&sample());
        assert!(text.starts_with('\n'));
        let claim = text.find("Requester's claim").unwrap();
        let signed = text.find("What will be signed").unwrap();
        let purpose = text.find("  Purpose (claimed by the requester): Send 1 ETH").unwrap();
        let account = text.find("  Account: 0xf39F").unwrap();
        assert!(claim < purpose && purpose < signed && signed < account);
        assert!(text.contains("Requested by: eth_wallet_backend"));
        assert!(text.contains("approve:  logosctl call evm_signer_cli approve ksh_abc 8c1e @/path/to/pwfile"));
        assert!(text.ends_with(&format!("reject:   logosctl call evm_signer_cli reject ksh_abc\n{RULE}")));
    }

    #[test]
    fn an_empty_claim_keeps_its_section() {
        let mut r = sample();
        r.claim_lines.clear();
        let text = render(&r);
        assert!(text.contains("Requester's claim"));
        assert!(text.contains("  (the requester made no claim)"));
    }

    #[test]
    fn strip_file_newline_drops_exactly_one() {
        assert_eq!(strip_file_newline("pw\n"), "pw");
        assert_eq!(strip_file_newline("pw\r\n"), "pw");
        assert_eq!(strip_file_newline("pw\n\n"), "pw\n");
        assert_eq!(strip_file_newline("pw"), "pw");
        assert_eq!(strip_file_newline(" pw \n"), " pw ");
        assert_eq!(strip_file_newline(""), "");
    }

    #[test]
    fn bundle_ids_normalise_like_the_keystore() {
        assert_eq!(normalise_bundle_id(" 0xAB12 "), "ab12");
        assert_eq!(normalise_bundle_id("ab12"), "ab12");
    }

    #[test]
    fn the_hint_is_total_safe() {
        let id = json!({ "approvers": ["evm_signer_ui"], "custodians": ["evm_keystore_ui"] });
        let hint = configure_hint(&id, "evm_signer_cli", "approvers");
        assert_eq!(
            hint,
            r#"logosctl call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui"]}'"#
        );
        let already = json!({ "approvers": ["evm_signer_ui", "evm_signer_cli"], "custodians": [] });
        assert!(configure_hint(&already, "evm_signer_cli", "approvers").contains(r#""approvers":["evm_signer_ui","evm_signer_cli"]"#));
        let empty = json!({ "ok": true });
        assert!(configure_hint(&empty, "evm_signer_cli", "approvers").contains(r#"{"approvers":["evm_signer_cli"],"custodians":[]}"#));
    }

    #[test]
    fn holds_reads_the_role_list() {
        let id = json!({ "approvers": ["evm_signer_ui", "evm_signer_cli"], "custodians": ["evm_keystore_ui"] });
        assert!(holds(&id, "evm_signer_cli", "approvers"));
        assert!(!holds(&id, "evm_signer_cli", "custodians"));
        assert!(!holds(&json!({}), "evm_signer_cli", "approvers"));
    }

    #[test]
    fn scrub_empties_the_string() {
        let mut s = String::from("secret");
        scrub(&mut s);
        assert!(s.is_empty());
    }
}
