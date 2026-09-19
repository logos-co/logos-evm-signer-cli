//! What this signer makes of the lines it is showing.
//!
//! The keystore hands an approver `render_lines` and nothing else — no structured
//! `to` or `data` — and that turns out to be the right input rather than a
//! limitation: an interpretation derived from the displayed text cannot describe
//! different bytes than the human is reading.
//!
//! Offline on every path, and additive: nothing here replaces a keystore line.

use logos_tx_decoder::{read_request, AbiDb};

use crate::tokenlist;
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
    // The same call `evm_signer_ui` makes over the C ABI: one request, one reading, so
    // the two surfaces cannot describe the same bytes differently.
    let read = read_request(db, render_lines);

    // Label by ITEM count, not by how many decoded. A request of one message and one
    // transaction decodes to a single leg, and an unlabelled reading of it would look
    // like a description of the whole request.
    let label = read.items > 1;
    let mut out = Vec::new();
    for leg in &read.legs {
        if label {
            out.push(format!("Item [{}]:", leg.index));
        }
        out.extend(leg.lines.iter().cloned());
        // AFTER the decoder's own reading, never mixed into it: the decoder says what it
        // can back, and this says what a token list on this device claims. Empty when no
        // list is loaded, which is the normal state for a signing device.
        out.extend(tokenlist::describe(leg.chain_id, &leg.to, &leg.call));
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

    /// The Uniswap app's swap, as the keystore renders it: 0.000001 ETH for at least
    /// 0.002621 USDT through SwapRouter02.
    fn swap_request() -> Vec<String> {
        let w = |h: &str| format!("{:0>64}", h);
        let inner = format!("04e45aaf{}{}{}{}{}{}{}", w("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                            w("dac17f958d2ee523a2206206994597c13d831ec7"), w("64"),
                            w("a1e277ea6b97effc5b61b3bf5de03f438981247e"), w("e8d4a51000"), w("a3d"), w("0"));
        let data = format!("0x5ae401dc{}{}{}{}{}{inner}{}", w("6aaef2e8"), w("40"), w("1"), w("20"), w("e4"), "0".repeat(56));
        vec![
            "Account: 0xa1E277eA6b97eFfc5b61B3BF5dE03F438981247E".into(),
            "1 item(s) to sign:".into(),
            "  [1] Transaction on chain 1".into(),
            "      To: 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".into(),
            "      Value: 0xe8d4a51000 (1000000000000)".into(),
            format!("      Data: {data}"),
        ]
    }

    #[test]
    fn a_swap_reads_as_what_it_does_here_too() {
        let out = interpret(&swap_request());
        for want in [
            "  Sends 0.000001 of the native coin with this call (value 1000000000000 wei).",
            "  Deadline: 2026-09-19 20:39:04 UTC (deadline 1789850344); the call reverts after it.",
            "        Sells exactly 0.000001 WETH (amountIn 1000000000000); WETH is a verified contract.",
            "        Buys at least 0.002621 USDT (amountOutMinimum 2621); USDT is a verified contract.",
            "        Pool fee: 0.01% (fee 100).",
        ] {
            assert!(out.iter().any(|l| l == want), "missing {want:?} in\n{}", out.join("\n"));
        }
        // Whose address the swap pays is not in the transaction, so this signer does not say.
        assert!(!out.join("\n").contains("account signing"));
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
