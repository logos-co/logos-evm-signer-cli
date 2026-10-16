//! What this signer works out for the prompt from what it is shown: who asked, by the name the
//! user's installed package gives it, and a Bitcoin request's figures added up. The rules are
//! `evm_signer_ui`'s (src/sheet_lines.cpp), so the two surfaces read a request alike.

use std::collections::BTreeSet;

/// Short and plain, so a name cannot carry a second id in brackets, a look-alike letter or a
/// direction mark: an ASCII letter first, then letters, digits, single spaces and `- . '` only.
fn plain_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 40 || !b[0].is_ascii_alphabetic() || b[b.len() - 1] == b' ' {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| {
        c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'\'') || (c == b' ' && b[i - 1] != b' ')
    })
}

/// What two names have to differ in to be told apart at a glance: letters and digits, any case.
fn folded(s: &str) -> String {
    s.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

/// The name the user's installed package gives `module`, or `None` when there is none to trust:
/// no name, one that is not short plain ASCII, or one another installed package wears too.
/// `installed` is every installed package as (name, displayName).
pub fn installed_name(module: &str, installed: &[(String, String)]) -> Option<String> {
    let mut names = installed
        .iter()
        .filter(|(name, display)| name == module && !display.is_empty())
        .map(|(_, display)| display.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter();
    // Two copies that disagree give neither name.
    let (Some(name), None) = (names.next(), names.next()) else { return None };
    if !plain_name(name) || name == module {
        return None;
    }
    if installed.iter().any(|(other, display)| other != module && folded(display) == folded(name)) {
        return None;
    }
    Some(name.to_string())
}

const COIN: u64 = 100_000_000;
const MAX_SATS: u64 = 21_000_000 * COIN;

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// An amount as the manager prints one, `<coins>.<eight digits> BTC`, at the start of `s`:
/// its satoshis and the rest of `s`.
fn amount(s: &str) -> Option<(u64, &str)> {
    let (whole, rest) = s.split_once('.')?;
    let (frac, rest) = (rest.get(..8)?, rest.get(8..)?.strip_prefix(" BTC")?);
    if !digits(whole) || whole.len() > 8 || !digits(frac) {
        return None;
    }
    let sats = whole.parse::<u64>().ok()? * COIN + frac.parse::<u64>().ok()?;
    (sats <= MAX_SATS).then_some((sats, rest))
}

fn btc(sats: u64) -> String {
    format!("{}.{:08} BTC", sats / COIN, sats % COIN)
}

/// `Change|Receive <amount> back to this wallet (m/<path>, checked)`.
fn own_output(l: &str) -> Option<u64> {
    let (sats, rest) = amount(l.strip_prefix("Change ").or_else(|| l.strip_prefix("Receive "))?)?;
    let path = rest.strip_prefix(" back to this wallet (m/")?.strip_suffix(", checked)")?;
    (!path.contains(['(', ')'])).then_some(sats)
}

/// `Send <amount> to <address>`, or `to a script with no address: <hex>`: its satoshis and payee.
fn payment(l: &str) -> Option<(u64, &str)> {
    let (sats, rest) = amount(l.strip_prefix("Send ")?)?;
    let to = rest.strip_prefix(" to ")?;
    match to.strip_prefix("a script with no address: ") {
        Some(hex) if !hex.is_empty() && hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) => {
            Some((sats, hex))
        }
        _ if digits_or_letters(to) => Some((sats, to)),
        _ => None,
    }
}

fn digits_or_letters(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric())
}

/// `Fee <grouped sats> sats, about <n>.<n> sat/vB, computed from the inputs`: the figure as
/// printed.
fn fee(l: &str) -> Option<&str> {
    let (grouped, rest) = l.strip_prefix("Fee ")?.split_once(' ')?;
    let mut groups = grouped.split(',');
    let first = groups.next()?;
    if !digits(first) || first.len() > 3 || !groups.all(|g| digits(g) && g.len() == 3) {
        return None;
    }
    let rate = rest.strip_prefix("sats, about ")?.strip_suffix(" sat/vB, computed from the inputs")?;
    let (whole, tenth) = rate.split_once('.')?;
    (digits(whole) && digits(tenth) && tenth.len() == 1).then_some(grouped)
}

/// `Spends <n> coin(s) worth <amount>`, then ` · replaceable (RBF)` or nothing.
fn spends(l: &str) -> Option<u64> {
    let rest = l.strip_prefix("Spends ")?;
    let (n, rest) = rest.split_once(' ')?;
    let rest = rest.strip_prefix("coin")?;
    let rest = rest.strip_prefix('s').unwrap_or(rest).strip_prefix(" worth ")?;
    let (sats, tail) = amount(rest)?;
    (digits(n) && (tail.is_empty() || tail == " · replaceable (RBF)")).then_some(sats)
}

/// Section 3 for a Bitcoin request, added up from section 2's own lines. Empty for anything that
/// is not one, so the EVM reading is untouched.
pub fn bitcoin_reading(lines: &[String]) -> Vec<String> {
    // The manager's Bitcoin layout: the wallet, the commitment, one item, then the PSBT's lines.
    if lines.len() < 4
        || !lines[0].starts_with("Wallet: ")
        || !lines[1].starts_with("Commitment: ")
        || lines[2] != "1 item(s) to sign:"
        || !lines[3].starts_with("  [1] Bitcoin ")
    {
        return Vec::new();
    }
    // Anything not read below, or figures that do not balance: section 2 stands alone.
    let whole = || {
        vec!["Interpreted: nothing to add — section 2 is the signer manager's whole reading of this \
              Bitcoin transaction."
            .to_string()]
    };

    enum At {
        Outputs,
        Spends,
        Done,
    }
    let (mut back, mut out, mut paid, mut inputs, mut outputs) = (0u64, 0u64, 0u64, 0u64, 0usize);
    let mut to = BTreeSet::new();
    let mut fee_text = String::new();
    let mut at = At::Outputs;
    for line in &lines[4..] {
        let Some(l) = line.strip_prefix("      ") else { return whole() };
        match at {
            At::Outputs => {
                if let Some(v) = own_output(l) {
                    back += v;
                    outputs += 1;
                } else if let Some((v, payee)) = payment(l) {
                    out += v;
                    to.insert(payee);
                    outputs += 1;
                } else if let (true, Some(f)) = (outputs > 0, fee(l)) {
                    let figure: String = f.chars().filter(|&c| c != ',').collect();
                    if figure.len() > 16 {
                        return whole();
                    }
                    paid = figure.parse().unwrap_or(u64::MAX);
                    fee_text = f.to_string();
                    at = At::Spends;
                } else {
                    return whole();
                }
            }
            At::Spends => match spends(l) {
                Some(v) => {
                    inputs = v;
                    at = At::Done;
                }
                None => return whole(),
            },
            At::Done => return whole(),
        }
        if back > MAX_SATS || out > MAX_SATS || paid > MAX_SATS {
            return whole();
        }
    }
    if !matches!(at, At::Done) || back + out + paid != inputs {
        return whole();
    }

    let mut r = vec!["Interpreted: Bitcoin — section 2's own figures, added up on this device".to_string()];
    if out == 0 {
        r.push(if paid == 0 {
            "  Everything comes back to this wallet, and there is no fee.".into()
        } else {
            format!("  Everything comes back to this wallet; you pay only the {fee_text}-sat fee.")
        });
        return r;
    }
    let to = if to.len() == 1 { "an address".to_string() } else { format!("{} addresses", to.len()) };
    let back = if back == 0 { "nothing comes back".to_string() } else { format!("{} comes back to this wallet", btc(back)) };
    let fee = match paid {
        0 => "no fee".to_string(),
        1 => format!("fee {fee_text} sat"),
        _ => format!("fee {fee_text} sats"),
    };
    r.push(format!("  Sends {} to {to} not shown to be this wallet's; {back}; {fee}.", btc(out)));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADLINE: &str = "Interpreted: Bitcoin — section 2's own figures, added up on this device";
    const WHOLE: &str =
        "Interpreted: nothing to add — section 2 is the signer manager's whole reading of this Bitcoin transaction.";

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Section 2 for one Bitcoin request, as signer_manager_module renders it.
    fn bitcoin(legs: &[&str]) -> Vec<String> {
        let mut out = lines(&[
            "Wallet: \"Savings\"",
            "Commitment: 9f86d081",
            "1 item(s) to sign:",
            "  [1] Bitcoin testnet4 · wallet \"Savings\", native segwit, account 0",
        ]);
        out.extend(legs.iter().map(|l| format!("      {l}")));
        out
    }

    fn read(legs: &[&str]) -> String {
        bitcoin_reading(&bitcoin(legs)).join("\n")
    }

    #[test]
    fn a_send_to_this_wallet_itself_costs_only_the_fee() {
        assert_eq!(
            read(&[
                "Change 0.00363024 BTC back to this wallet (m/84'/1'/0'/1/0, checked)",
                "Receive 0.00003000 BTC back to this wallet (m/84'/1'/0'/0/0, checked)",
                "Fee 141 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00366165 BTC · replaceable (RBF)",
            ]),
            format!("{HEADLINE}\n  Everything comes back to this wallet; you pay only the 141-sat fee.")
        );
    }

    #[test]
    fn a_payment_out_says_what_leaves_and_what_comes_back() {
        assert_eq!(
            read(&[
                "Send 0.00003000 BTC to tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                "Change 0.00363024 BTC back to this wallet (m/84'/1'/0'/1/0, checked)",
                "Fee 141 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00366165 BTC",
            ]),
            format!(
                "{HEADLINE}\n  Sends 0.00003000 BTC to an address not shown to be this wallet's; \
                 0.00363024 BTC comes back to this wallet; fee 141 sats."
            )
        );
    }

    #[test]
    fn two_payees_and_a_grouped_fee_with_nothing_back() {
        assert_eq!(
            read(&[
                "Send 0.00100000 BTC to tb1qaaaa",
                "Send 0.00048810 BTC to a script with no address: 51",
                "Fee 1,190 sats, about 7.3 sat/vB, computed from the inputs",
                "Spends 2 coins worth 0.00150000 BTC · replaceable (RBF)",
            ]),
            format!(
                "{HEADLINE}\n  Sends 0.00148810 BTC to 2 addresses not shown to be this wallet's; \
                 nothing comes back; fee 1,190 sats."
            )
        );
    }

    #[test]
    fn two_payments_to_one_address_are_one_address() {
        assert_eq!(
            read(&[
                "Send 0.00001000 BTC to tb1qaaaa",
                "Send 0.00001000 BTC to tb1qaaaa",
                "Fee 100 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00002100 BTC",
            ]),
            format!(
                "{HEADLINE}\n  Sends 0.00002000 BTC to an address not shown to be this wallet's; \
                 nothing comes back; fee 100 sats."
            )
        );
    }

    #[test]
    fn anything_it_cannot_read_whole_it_does_not_summarise() {
        // A line it does not know.
        assert_eq!(
            read(&[
                "Data output (OP_RETURN, 6 bytes) carrying 0.00000000 BTC",
                "Change 0.00001000 BTC back to this wallet (m/84'/1'/0'/1/0, checked)",
                "Fee 100 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00001100 BTC",
            ]),
            WHOLE
        );
        // Figures that do not balance.
        assert_eq!(
            read(&[
                "Change 0.00001000 BTC back to this wallet (m/84'/1'/0'/1/0, checked)",
                "Fee 100 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00001101 BTC",
            ]),
            WHOLE
        );
        // Lines out of the manager's order.
        assert_eq!(
            read(&[
                "Change 0.00001000 BTC back to this wallet (m/84'/1'/0'/1/0, checked)",
                "Spends 1 coin worth 0.00001100 BTC",
                "Fee 100 sats, about 1.0 sat/vB, computed from the inputs",
            ]),
            WHOLE
        );
        // No fee or inputs line.
        assert_eq!(read(&["Send 0.00001000 BTC to tb1qaaaa"]), WHOLE);
        // A change line the manager did not check.
        assert_eq!(
            read(&[
                "Change 0.00001000 BTC back to this wallet (m/84'/1'/0'/1/0)",
                "Fee 100 sats, about 1.0 sat/vB, computed from the inputs",
                "Spends 1 coin worth 0.00001100 BTC",
            ]),
            WHOLE
        );
    }

    #[test]
    fn an_evm_request_is_left_to_the_decoder_untouched() {
        let tx = lines(&[
            "Account: 0xf39F…2266",
            "Commitment: 9f86d081",
            "1 item(s) to sign:",
            "  [1] Transaction on chain 1",
            "      To: 0xC02a…6Cc2",
            "      Value: 0",
        ]);
        assert!(bitcoin_reading(&tx).is_empty());
        let message = lines(&[
            "Account: 0xf39F…2266",
            "Commitment: 9f86d081",
            "1 item(s) to sign:",
            "  [1] Sign text message",
            "      Text: hello",
        ]);
        assert!(bitcoin_reading(&message).is_empty());
        assert!(bitcoin_reading(&[]).is_empty());
    }

    fn installed() -> Vec<(String, String)> {
        [
            ("bitcoin_wallet_core_module", "Bitcoin Wallet Core"),
            ("bitcoin_wallet_ui", "Bitcoin Wallet"),
            ("signer_manager_module", ""),
            ("evm_signer_ui", "Signer"),
        ]
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect()
    }

    fn named(display: &str) -> Option<String> {
        installed_name("some_module", &[("some_module".into(), display.into())])
    }

    #[test]
    fn the_name_is_the_installed_packages_own() {
        assert_eq!(installed_name("bitcoin_wallet_core_module", &installed()).as_deref(), Some("Bitcoin Wallet Core"));
        // A module nothing installed names, and a package with no name.
        assert_eq!(installed_name("signer_probe", &installed()), None);
        assert_eq!(installed_name("signer_manager_module", &installed()), None);
    }

    #[test]
    fn a_name_that_is_not_short_plain_ascii_is_dropped() {
        assert_eq!(named("Bitcoin Wallet (bitcoin_wallet_core_module)"), None);
        assert_eq!(named("Bitcoin \u{202E}Wallet"), None);
        assert_eq!(named("Bitc\u{043E}in Wallet"), None);
        assert_eq!(named("Bitcoin\nWallet"), None);
        assert_eq!(named("A name that goes on and on past forty chars"), None);
        assert_eq!(named("some_module"), None);
        assert_eq!(named("Bob's Wallet 2.0").as_deref(), Some("Bob's Wallet 2.0"));
    }

    #[test]
    fn a_name_another_package_also_wears_names_neither() {
        let mut with_impostor = installed();
        with_impostor.push(("evil_module".into(), "bitcoin wallet-core.".into()));
        assert_eq!(installed_name("bitcoin_wallet_core_module", &with_impostor), None);
        assert_eq!(installed_name("evil_module", &with_impostor), None);
    }

    #[test]
    fn two_copies_keep_the_name_only_if_they_agree() {
        let copies = |a: &str, b: &str| {
            installed_name("some_module", &[("some_module".into(), a.into()), ("some_module".into(), b.into())])
        };
        assert_eq!(copies("Wallet", "Wallet Two"), None);
        assert_eq!(copies("Wallet", "Wallet").as_deref(), Some("Wallet"));
    }
}
