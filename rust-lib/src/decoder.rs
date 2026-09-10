//! What this signer makes of the lines it is showing.
//!
//! The keystore hands an approver `render_lines` and nothing else — no structured
//! `to` or `data` — and that turns out to be the right input rather than a
//! limitation: an interpretation derived from the displayed text cannot describe
//! different bytes than the human is reading.
//!
//! Offline on every path, and additive: nothing here replaces a keystore line.

use logos_tx_decoder::{decode_call, describe, parse_render_lines, AbiDb};
use std::sync::OnceLock;

/// Parsing ~430KB of embedded ABI JSON per request would be absurd, and this module
/// is `concurrency: "multi"` — several `show` calls can be in flight at once.
fn db() -> Option<&'static AbiDb> {
    static DB: OnceLock<Option<AbiDb>> = OnceLock::new();
    DB.get_or_init(|| AbiDb::embedded().ok()).as_ref()
}

/// The lines of section 3. Empty is NORMAL — a message, a digest, or a selector this
/// signer does not know — and is never an error: the prompt drops the section and the
/// keystore's own words stand alone, exactly as they did before this existed.
pub fn interpret(render_lines: &[String]) -> Vec<String> {
    let Some(db) = db() else { return Vec::new() };
    let scan = parse_render_lines(render_lines);

    // Label by ITEM count, not by how many decoded. A request of one message and one
    // transaction decodes to a single leg, and an unlabelled reading of it would look
    // like a description of the whole request.
    let label = scan.items > 1;
    let mut out = Vec::new();
    for leg in &scan.legs {
        if label {
            out.push(format!("Item [{}]:", leg.index));
        }
        out.extend(describe(&decode_call(db, leg.chain_id, &leg.to, &leg.data)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const WETH_TRANSFER: &[&str] = &[
        "Account: 0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        "1 item(s) to sign:",
        "  [1] Transaction on chain 1",
        "      To: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "      Value: 0",
        "      Selector: 0xa9059cbb",
        "      Data: 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045000000000000000000000000000000000000000000000000000000003b9aca00",
    ];

    #[test]
    fn a_known_address_reads_as_verified() {
        let out = interpret(&lines(WETH_TRANSFER)).join("\n");
        assert!(out.contains("VERIFIED"), "{out}");
        assert!(out.contains("WETH"), "{out}");
        assert!(out.contains("transfer(address,uint256)"), "{out}");
    }

    #[test]
    fn a_selector_match_alone_says_so() {
        let mut l = lines(WETH_TRANSFER);
        l[3] = "      To: 0x000000000000000000000000000000000000dEaD".into();
        let out = interpret(&l).join("\n");
        assert!(out.contains("UNVERIFIED"), "{out}");
        assert!(!out.contains("WETH"), "{out}");
    }

    #[test]
    fn nothing_decodable_is_not_an_error() {
        assert!(interpret(&lines(&["Account: 0x1", "  [1] Sign text message"])).is_empty());
        assert!(interpret(&[]).is_empty());
    }

    #[test]
    fn a_reading_of_one_item_among_several_carries_its_number() {
        let mut l = lines(&["Account: 0xd8da", "2 item(s) to sign:", "  [1] Sign text message"]);
        l.extend(lines(WETH_TRANSFER)[2..].iter().cloned());
        l[3] = "  [2] Transaction on chain 1".into();
        let out = interpret(&l);
        assert_eq!(out.first().map(String::as_str), Some("Item [2]:"));
    }
}
