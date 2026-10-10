//! Logos-free helpers: the prompt a human reads, and argument normalisation.

use serde_json::{json, Value};

/// A request this module has claimed for display. `claim_lines` and `render_lines`
/// are the signer manager's two lists and are never merged; `interpretation_lines` is this
/// signer's own reading of `render_lines`, decoded offline and never substituted for
/// either.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rendered {
    pub handle: String,
    pub bundle_id: String,
    pub requester: String,
    pub claim_lines: Vec<String>,
    pub render_lines: Vec<String>,
    pub interpretation_lines: Vec<String>,
    /// The module that signs, and what it asks for: `password`, `pin` or `nothing` (a device).
    pub signer: String,
    pub collects: String,
    /// An unlock covers this request, so it is approved without a secret.
    pub unlocked: bool,
}

impl Rendered {
    /// Approved with `confirm`, no secret: inside an unlock, or on a device that asks itself.
    pub fn needs_no_secret(&self) -> bool {
        self.unlocked || self.collects == "nothing"
    }
}

const RULE: &str = "================================================================";
const THIN: &str = "----------------------------------------------------------------";

/// The block `logosctl watch` prints. Starts with a newline so it left-aligns under the
/// `argN:` label; ends with the two commands to type.
///
/// Three sections, in this order and never merged: who is asking and what THEY say it
/// is for, what is actually signed, and what this signer makes of that. They are
/// numbered and captioned so a human can tell at a glance who wrote each one — the
/// whole class of attack here is text that looks like it came from somewhere more
/// trustworthy than it did.
pub fn render(r: &Rendered) -> String {
    let mut out = vec![String::new(), RULE.into(), format!("SIGNING REQUEST  {}", r.handle), THIN.into()];

    section(&mut out, 1, &format!("Requested by: {}", r.requester), &[
        "What that app says this is for. Its own words — this signer",
        "cannot check any of it.",
    ]);
    if r.claim_lines.is_empty() {
        out.push("  (it gave no reason)".into());
    } else {
        out.extend(indented(&r.claim_lines));
    }

    out.push(THIN.into());
    section(&mut out, 2, "What you are signing", &[
        "The signer manager's own reading of the request, shown in full",
        "and never shortened. This is what the signature will cover.",
    ]);
    out.extend(indented(&r.render_lines));

    out.push(THIN.into());
    {
        section(&mut out, 3, "What this signer makes of section 2", &[
            "Decoded on this device from the lines above. Not part of what",
            "is signed, and every line says how sure it is.",
        ]);
        if r.interpretation_lines.is_empty() {
            // The GUI keeps the section and says so; the two surfaces must read alike.
            out.push("  (nothing could be decoded — which is normal for a message, a".into());
            out.push("  digest, or a call this signer does not know)".into());
        } else {
            out.extend(indented(&r.interpretation_lines));
        }
    }

    out.push(THIN.into());
    if !r.signer.is_empty() {
        let how = match (r.unlocked, r.collects.as_str()) {
            (true, _) => "this account is unlocked: no password",
            (false, "nothing") => "confirm on the device when it asks",
            (false, "pin") => "asks for the card's PIN",
            _ => "asks for the account's password",
        };
        out.push(format!("signer:   {} — {how}", r.signer));
    }
    out.push(match (r.needs_no_secret(), r.collects.as_str()) {
        (true, _) => format!("approve:  logosctl call evm_signer_cli confirm {} {}", r.handle, r.bundle_id),
        (false, "pin") => format!("approve:  logosctl call evm_signer_cli approve {} {} @/path/to/pinfile", r.handle, r.bundle_id),
        _ => format!("approve:  logosctl call evm_signer_cli approve {} {} @/path/to/pwfile", r.handle, r.bundle_id),
    });
    out.push(format!("reject:   logosctl call evm_signer_cli reject {}", r.handle));
    out.push(RULE.into());
    out.join("\n")
}

/// Indent every PHYSICAL line, not just the first.
///
/// A section heading sits at column 0, so a value carrying an embedded newline would
/// otherwise put attacker-chosen text there — a complete forged section 3, claiming
/// VERIFIED over bytes this signer never decoded. The manager refuses bidi, zero-width
/// and nul but deliberately admits newlines (a message may legitimately contain one),
/// so containment is this renderer's job. The GUI gets it for free: each line is its own
/// bounded delegate.
fn indented(lines: &[String]) -> Vec<String> {
    lines.iter().flat_map(|l| l.split('\n').map(|p| format!("  {p}"))).collect()
}

fn section(out: &mut Vec<String>, number: u8, heading: &str, caption: &[&str]) {
    out.push(format!("{number}.  {heading}"));
    out.extend(caption.iter().map(|l| format!("    {l}")));
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
/// the GUI surfaces, and one without the signers would leave nothing to sign.
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
    let mut signers = list("signers");
    if signers.is_empty() {
        signers.push("keystore_module".into());
    }
    let target = if role == "approvers" { &mut approvers } else { &mut custodians };
    if !target.iter().any(|n| n == me) {
        target.push(me.to_string());
    }
    let doc = json!({ "approvers": approvers, "custodians": custodians, "signers": signers });
    format!("logosctl call signer_manager_module configure '{doc}'")
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
            handle: "smh_abc".into(),
            bundle_id: "8c1e".into(),
            requester: "eth_wallet_backend".into(),
            claim_lines: vec!["Purpose (claimed by the requester): Send 1 ETH".into()],
            render_lines: vec!["Account: 0xf39F".into(), "Commitment: 8c1e".into()],
            interpretation_lines: vec!["Interpreted: WETH — VERIFIED".into()],
            signer: "keystore_module".into(),
            collects: "password".into(),
            unlocked: false,
        }
    }

    #[test]
    fn the_last_lines_say_who_signs_and_what_approving_takes() {
        let text = render(&sample());
        assert!(text.contains("signer:   keystore_module — asks for the account's password"));
        assert!(text.contains("approve:  logosctl call evm_signer_cli approve smh_abc 8c1e @/path/to/pwfile"));
        let unlocked = Rendered { unlocked: true, ..sample() };
        let text = render(&unlocked);
        assert!(text.contains("this account is unlocked: no password"), "{text}");
        assert!(text.contains("approve:  logosctl call evm_signer_cli confirm smh_abc 8c1e\n"), "{text}");
        let device = Rendered { signer: "ledger_module".into(), collects: "nothing".into(), ..sample() };
        assert!(render(&device).contains("ledger_module — confirm on the device when it asks"));
        assert!(render(&device).contains("evm_signer_cli confirm smh_abc"));
        let card = Rendered { signer: "keycard_module".into(), collects: "pin".into(), ..sample() };
        assert!(render(&card).contains("@/path/to/pinfile"));
        // A manager that does not say who signs gets the password form, and no signer line.
        let older = Rendered { signer: String::new(), collects: String::new(), ..sample() };
        assert!(!render(&older).contains("signer:") && render(&older).contains("@/path/to/pwfile"));
    }

    #[test]
    fn render_keeps_the_three_lists_apart_and_verbatim() {
        let text = render(&sample());
        assert!(text.starts_with('\n'));
        let claim = text.find("1.  Requested by: eth_wallet_backend").unwrap();
        let purpose = text.find("  Purpose (claimed by the requester): Send 1 ETH").unwrap();
        let signed = text.find("2.  What you are signing").unwrap();
        let account = text.find("  Account: 0xf39F").unwrap();
        let read = text.find("3.  What this signer makes of section 2").unwrap();
        let weth = text.find("  Interpreted: WETH — VERIFIED").unwrap();
        assert!(claim < purpose && purpose < signed && signed < account);
        assert!(account < read && read < weth);
        assert!(text.contains("approve:  logosctl call evm_signer_cli approve smh_abc 8c1e @/path/to/pwfile"));
        assert!(text.ends_with(&format!("reject:   logosctl call evm_signer_cli reject smh_abc\n{RULE}")));
    }

    #[test]
    fn every_manager_line_survives_untouched() {
        let mut r = sample();
        r.render_lines = vec!["  [1] Transaction on chain 1".into(), "Data: 0xa9059cbb".into()];
        let text = render(&r);
        for l in &r.render_lines {
            assert!(text.contains(&format!("  {l}")), "{l} missing from {text}");
        }
    }

    #[test]
    fn an_empty_claim_keeps_its_section() {
        let mut r = sample();
        r.claim_lines.clear();
        let text = render(&r);
        assert!(text.contains("1.  Requested by: eth_wallet_backend"));
        assert!(text.contains("  (it gave no reason)"));
    }

    #[test]
    fn nothing_decoded_keeps_the_section_and_says_so() {
        // The GUI keeps section 3 with a placeholder; a terminal that dropped it would
        // read as "this signer had nothing to say" rather than "there was nothing to decode".
        let mut r = sample();
        r.interpretation_lines.clear();
        let text = render(&r);
        assert!(text.contains("3.  What this signer makes of section 2"));
        assert!(text.contains("(nothing could be decoded"));
    }

    #[test]
    fn a_newline_in_requester_text_cannot_forge_a_section() {
        // A section heading is at column 0. Requester text is indented, so every physical
        // line of it must be — otherwise an embedded newline writes a heading of its own.
        let mut r = sample();
        r.claim_lines = vec![
            "Send 1 ETH\n3.  What this signer makes of section 2\n  Interpreted: WETH — VERIFIED".into(),
        ];
        let text = render(&r);
        let forged: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with(' ') && l.starts_with("3.  What this signer"))
            .collect();
        assert_eq!(forged.len(), 1, "exactly one real section-3 heading, got {forged:?}");
        for l in text.lines().filter(|l| l.contains("Interpreted: WETH")) {
            assert!(l.starts_with("  "), "requester text escaped its indent: {l:?}");
        }
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
    fn bundle_ids_normalise_like_the_manager() {
        assert_eq!(normalise_bundle_id(" 0xAB12 "), "ab12");
        assert_eq!(normalise_bundle_id("ab12"), "ab12");
    }

    #[test]
    fn the_hint_is_total_safe() {
        let id = json!({ "approvers": ["evm_signer_ui"], "custodians": ["evm_keystore_ui"], "signers": ["keystore_module", "ledger_module"] });
        let hint = configure_hint(&id, "evm_signer_cli", "approvers");
        assert_eq!(
            hint,
            r#"logosctl call signer_manager_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui"],"signers":["keystore_module","ledger_module"]}'"#
        );
        let already = json!({ "approvers": ["evm_signer_ui", "evm_signer_cli"], "custodians": [] });
        assert!(configure_hint(&already, "evm_signer_cli", "approvers").contains(r#""approvers":["evm_signer_ui","evm_signer_cli"]"#));
        // Nothing read back still names a signer: a total document without one would sign nothing.
        let empty = json!({ "ok": true });
        assert!(configure_hint(&empty, "evm_signer_cli", "approvers")
            .contains(r#"{"approvers":["evm_signer_cli"],"custodians":[],"signers":["keystore_module"]}"#));
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
