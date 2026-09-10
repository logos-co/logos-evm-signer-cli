//! What a token list on this device says about the address being called.
//!
//! Strictly the signer's own layer, and strictly UNVERIFIED. `logos_tx_decoder` answers
//! only what it can back — its ABI database says an address declares a function, and that
//! is what `VERIFIED` means there. A token list backs nothing about code: it says an
//! address has a name and a unit, and anyone who can add a custom token can make a hostile
//! address carry a friendly symbol.
//!
//! So this never touches the decoder's tiers. It adds lines that say where they came from,
//! under a heading that says the same, and the raw values above them do not move.
//!
//! `token_list_module` is an OPTIONAL dependency. Absent is a normal state — the prompt is
//! then exactly what it was before this existed.

use logos_tx_decoder::{Arg, DecodedCall};
use serde_json::Value;

/// Bounded: this runs while a human waits at a prompt, and a token list that cannot answer
/// must cost the naming rather than the approval.
const BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Which argument of a call is an amount in the token's own units, by signature.
///
/// The signer's OWN table, deliberately not borrowed from the decoder: this is the
/// unverified layer, and a position table that travelled would invite the decoder's
/// stricter promise to travel with it. A `uint256` is as likely to be a deadline or a
/// token id, so only the ERC-20 trio whose unit the standard itself fixes appears here.
const AMOUNT_ARGS: &[(&str, usize)] = &[
    ("transfer(address,uint256)", 1),
    ("approve(address,uint256)", 1),
    ("transferFrom(address,address,uint256)", 2),
];

/// One row as the module answered it.
#[cfg_attr(not(feature = "logos_module"), allow(dead_code))]
struct Listed {
    symbol: String,
    name: String,
    decimals: u8,
    source: String,
}

/// Without the module runtime there is no client to ask, and the layer is simply absent —
/// which is also exactly what happens on a device with no token list loaded. That symmetry
/// is why the pure parts below stay testable off-runtime.
#[cfg(not(feature = "logos_module"))]
fn ask(_chain_id: u64, _address: &str) -> Option<Listed> {
    None
}

#[cfg(feature = "logos_module")]
fn ask(chain_id: u64, address: &str) -> Option<Listed> {
    // The generated clients are include!d into `glue`, so this is their path — not the
    // crate root, which is where the obvious spelling looks for them.
    let raw = crate::glue::token_list_module::TokenListModuleClient::new()
        .get_tokens_by_address_with_timeout(
            chain_id as i64,
            &serde_json::to_string(&[address]).ok()?,
            BUDGET,
        )
        .ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    if v.get("ok") != Some(&Value::Bool(true)) {
        return None;
    }
    let t = v.get("tokens")?.as_array()?.first()?;
    Some(Listed {
        symbol: t.get("symbol")?.as_str()?.to_string(),
        name: t.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        decimals: u8::try_from(t.get("decimals")?.as_u64()?).ok()?,
        source: t.get("source").and_then(Value::as_str).unwrap_or("unknown").to_string(),
    })
}

/// Lines about the called address, or none. Appended after the decoder's own reading of
/// the same leg, never mixed into it.
pub fn describe(chain_id: u64, to: &str, d: &DecodedCall) -> Vec<String> {
    let Some(t) = ask(chain_id, to) else { return Vec::new() };
    lines(&t, d)
}

/// The wording, kept apart from the lookup so it is testable without the module runtime.
/// This is where the claim is made, so it is the part worth testing.
fn lines(t: &Listed, d: &DecodedCall) -> Vec<String> {
    let named = if t.name.is_empty() || t.name == t.symbol {
        t.symbol.clone()
    } else {
        format!("{} ({})", t.symbol, t.name)
    };
    let mut out = vec![format!(
        "Token list ({}) says this address is {} — a NAME, not a check of the code.",
        t.source, named
    )];

    if let Some(scaled) = amount(d, t.decimals) {
        // Conditional on purpose: the position of the amount comes from the signature the
        // decoder matched, which may itself be a guess. Saying so costs one clause and
        // keeps this line from reading like the decoder's verified one.
        out.push(format!(
            "  If that reading is right, the amount is {} {}.",
            scaled, t.symbol
        ));
    }
    out
}

fn amount(d: &DecodedCall, decimals: u8) -> Option<String> {
    let sig = d.function.as_ref()?.signature.as_str();
    let idx = AMOUNT_ARGS.iter().find(|(s, _)| *s == sig)?.1;
    let raw = d.args.as_ref()?.get(idx).and_then(|a: &Arg| a.value.as_deref())?;
    scale(raw, decimals)
}

/// Exact, never rounded — the same rule the keystore's own figures follow. A value this
/// cannot read scales to nothing rather than to a guess.
fn scale(raw: &str, decimals: u8) -> Option<String> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d = decimals as usize;
    if d == 0 {
        return Some(raw.to_string());
    }
    let padded = format!("{:0>width$}", raw, width = d + 1);
    let (whole, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    Some(if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    })
}

#[cfg(test)]
mod tests {
    use super::{lines, scale, Listed};
    use logos_tx_decoder::{decode_call, AbiDb};

    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const TRANSFER: &str = "0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045000000000000000000000000000000000000000000000000000000003b9aca00";

    fn listed(source: &str) -> Listed {
        Listed {
            symbol: "USDC".into(),
            name: "USD Coin".into(),
            decimals: 6,
            source: source.into(),
        }
    }

    fn rendered(source: &str, data: &str) -> String {
        let db = AbiDb::embedded().unwrap();
        lines(&listed(source), &decode_call(&db, 1, USDC, data)).join("\n")
    }

    #[test]
    fn the_name_is_offered_as_a_name_and_never_as_a_check() {
        // The decoder owns the word VERIFIED. This layer must not borrow it, in any form.
        let out = rendered("embedded", TRANSFER);
        assert!(out.contains("USDC (USD Coin)"), "{out}");
        assert!(out.contains("a NAME, not a check of the code"), "{out}");
        assert!(!out.contains("VERIFIED"), "{out}");
    }

    #[test]
    fn the_list_that_answered_is_named_on_the_line() {
        // A user can add a custom token, so a friendly symbol on a hostile address is
        // reachable. Naming it is allowed; doing it anonymously is not.
        for src in ["embedded", "downloaded", "custom"] {
            let out = rendered(src, TRANSFER);
            assert!(out.contains(&format!("Token list ({src})")), "{src}: {out}");
        }
    }

    #[test]
    fn the_amount_is_restated_in_the_listed_units_and_hedged() {
        // 1_000_000_000 raw at six decimals is 1000 USDC. The hedge matters: the argument
        // position comes from the signature the decoder matched, which may be a guess.
        let out = rendered("embedded", TRANSFER);
        assert!(out.contains("the amount is 1000 USDC"), "{out}");
        assert!(out.contains("If that reading is right"), "{out}");
    }

    #[test]
    fn a_signature_this_layer_does_not_know_restates_nothing() {
        // Only the ERC-20 trio has a standard-fixed unit. Anything else could be a
        // deadline or a token id, and scaling one of those invents a number.
        let out = rendered("embedded", "0x70a08231000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045");
        assert!(out.contains("Token list"), "the name still stands: {out}");
        assert!(!out.contains("the amount is"), "{out}");
    }

    #[test]
    fn six_decimals_is_not_eighteen() {
        // The failure this exists to avoid, stated as a test: the same integer read at the
        // wrong scale is wrong by a factor of a trillion, in the direction that looks
        // harmless.
        assert_eq!(scale("1000000000", 6).unwrap(), "1000");
        assert_eq!(scale("1000000000", 18).unwrap(), "0.000000001");
    }

    #[test]
    fn nothing_is_rounded_however_long_the_number_is() {
        assert_eq!(scale("1", 18).unwrap(), "0.000000000000000001");
        assert_eq!(scale("123456789012345678901", 18).unwrap(), "123.456789012345678901");
    }

    #[test]
    fn a_whole_number_shows_no_point_and_zero_decimals_is_the_integer() {
        assert_eq!(scale("5000000", 6).unwrap(), "5");
        assert_eq!(scale("42", 0).unwrap(), "42");
    }

    #[test]
    fn anything_that_is_not_a_decimal_integer_scales_to_nothing() {
        for bad in ["", "0x1f", "12.5", "-1", "1e18"] {
            assert!(scale(bad, 18).is_none(), "{bad}");
        }
    }
}
