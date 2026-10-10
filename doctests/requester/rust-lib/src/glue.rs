//! The requester half of the evm_signer_cli doc-test. It can ASK and can never APPROVE:
//! every signature it reports exists because a human typed `logosctl call evm_signer_cli
//! approve …`. Method-driven, so the spec controls every step.

use serde_json::{json, Value};
use std::str::FromStr;

type Receipts = std::sync::Mutex<std::collections::HashMap<String, String>>;

/// Foundry's well-known account 0. A published test key: never fund it.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const VAULT_PASSWORD: &str = "doctest-pw";
/// Foundry's test phrase, imported as a regtest Bitcoin wallet for the Bitcoin round.
const PHRASE: &str = "test test test test test test test test test test test junk";
const BTC_PASSWORD: &str = "btc-pw";

pub trait EvmSignerCliProbeModule: Send + 'static {
    /// Import the test key (Tier D — this fixture must be the keystore's custodian). `{ ok, address }`.
    fn setup(&mut self) -> String;
    /// Ask the manager for a signature over `message`. `{ ok, handle }`; the receipt stays here.
    fn request(&mut self, message: String) -> String;
    /// `{ ok, state, reason?, signed? }` — collects and acknowledges the result once approved.
    fn outcome(&mut self, handle: String) -> String;
    /// Give up on a request.
    fn cancel(&mut self, handle: String) -> bool;
    /// Unlock the test account for this fixture's own requests, as the manager's custodian (the
    /// keys app's role): `count` signatures, each confirmed or none of them shown.
    fn unlock(&mut self, count: i64, confirm: bool) -> String;
    /// Import the test phrase as a regtest native segwit wallet, as the keystore's custodian.
    /// `{ ok, group }`.
    fn setup_bitcoin(&mut self) -> String;
    /// Ask the manager to sign a PSBT spending the wallet's first coin: 60,000 sats out, 39,000
    /// back as change, 1,000 fee. Built offline from the wallet's xpub. `{ ok, handle }`.
    fn request_psbt(&mut self) -> String;
    /// Unlock the Bitcoin wallet for this fixture's own requests, as `unlock` does the account.
    fn unlock_bitcoin(&mut self, count: i64, confirm: bool) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct EvmSignerCliProbeModuleImpl {
    receipts: Receipts,
    /// The Bitcoin wallet: its group, its account xpub, its master fingerprint.
    bitcoin: std::sync::Mutex<Option<(String, String, String)>>,
}

/// A PSBT spending the wallet's first receive coin to a stranger, change to its first change key.
/// The funding is made up and nothing is broadcast.
fn psbt_for(xpub: &str, fingerprint: &str) -> Result<String, String> {
    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
    use bitcoin::{absolute::LockTime, transaction::Version};
    use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, Psbt, ScriptBuf, Sequence};
    use bitcoin::{Transaction, TxIn, TxOut, Txid, Witness};
    let e = |e: &dyn std::fmt::Display| e.to_string();
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let account = Xpub::from_str(xpub).map_err(|x| e(&x))?;
    let fp = Fingerprint::from_str(fingerprint).map_err(|x| e(&x))?;
    let key = |change: u32| -> Result<CompressedPublicKey, String> {
        let path = [ChildNumber::Normal { index: change }, ChildNumber::Normal { index: 0 }];
        Ok(CompressedPublicKey(account.derive_pub(&secp, &path).map_err(|x| e(&x))?.public_key))
    };
    let (receive, change) = (key(0)?, key(1)?);
    let input = |txid: Txid, sequence: Sequence| TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    };
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(Txid::from_str(&"11".repeat(32)).map_err(|x| e(&x))?, Sequence::MAX)],
        output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: ScriptBuf::new_p2wpkh(&receive.wpubkey_hash()) }],
    };
    // Not this wallet's: the key of secret 1, the generator point.
    let theirs = CompressedPublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .map_err(|x| e(&x))?;
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(funding.compute_txid(), Sequence::ENABLE_RBF_NO_LOCKTIME)],
        output: vec![
            TxOut { value: Amount::from_sat(60_000), script_pubkey: Address::p2wpkh(&theirs, Network::Regtest).script_pubkey() },
            TxOut { value: Amount::from_sat(39_000), script_pubkey: ScriptBuf::new_p2wpkh(&change.wpubkey_hash()) },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).map_err(|x| e(&x))?;
    let path = |c: u32| DerivationPath::from_str(&format!("m/84'/1'/0'/{c}/0")).map_err(|x| e(&x));
    psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(funding);
    psbt.inputs[0].bip32_derivation.insert(receive.0, (fp, path(0)?));
    psbt.outputs[1].bip32_derivation.insert(change.0, (fp, path(1)?));
    Ok(psbt.to_string())
}

/// How many signatures a signed PSBT carries, or `None` for anything else.
fn psbt_signatures(item: &Value) -> Option<usize> {
    let psbt = bitcoin::Psbt::from_str(item.as_str()?).ok()?;
    Some(psbt.inputs.iter().map(|i| i.partial_sigs.len() + usize::from(i.tap_key_sig.is_some())).sum())
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

fn parse(reply: Result<String, impl std::fmt::Debug>) -> Result<Value, String> {
    let raw = reply.map_err(|e| format!("{e:?}"))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(v.get("error").and_then(Value::as_str).unwrap_or("call refused").to_string());
    }
    Ok(v)
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

impl EvmSignerCliProbeModule for EvmSignerCliProbeModuleImpl {
    fn setup(&mut self) -> String {
        match parse(modules().keystore_module.import_private_key(TEST_KEY, VAULT_PASSWORD)) {
            Ok(v) => json!({ "ok": true, "address": text(&v, "address") }).to_string(),
            Err(e) => err(format!("import failed: {e}")),
        }
    }

    fn request(&mut self, message: String) -> String {
        let intent = json!({
            "address": ADDRESS,
            "purpose": format!("Doc-test: sign \"{message}\""),
            "legs": [
                { "kind": "message", "text": message },
                { "kind": "tx", "chain_id": 1, "tx": {
                    "to": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    "value": "0",
                    "nonce": "0",
                    "gas_limit": "60000",
                    "data": "0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045000000000000000000000000000000000000000000000000000000003b9aca00"
                }}
            ]
        });
        match parse(modules().signer_manager_module.request_approval(&intent.to_string())) {
            Ok(v) => {
                let (handle, receipt) = (text(&v, "handle"), text(&v, "receipt"));
                self.receipts.lock().unwrap().insert(handle.clone(), receipt);
                json!({ "ok": true, "handle": handle }).to_string()
            }
            Err(e) => err(format!("request_approval refused: {e}")),
        }
    }

    fn outcome(&mut self, handle: String) -> String {
        let Some(receipt) = self.receipts.lock().unwrap().get(&handle).cloned() else {
            return err("no receipt for that handle");
        };
        let status = match parse(modules().signer_manager_module.approval_status(&handle, &receipt)) {
            Ok(v) => v,
            Err(e) => return err(format!("approval_status: {e}")),
        };
        let (state, reason) = (text(&status, "state"), text(&status, "reason"));
        if reason != "approved" {
            return json!({ "ok": true, "state": state, "reason": reason }).to_string();
        }
        match parse(modules().signer_manager_module.fetch_result(&handle, &receipt)) {
            Ok(v) => {
                let signed = v.get("signed").cloned().unwrap_or(Value::Null);
                let _ = modules().signer_manager_module.ack_result(&handle, &receipt);
                let psbt = signed.get(0).and_then(psbt_signatures);
                json!({ "ok": true, "state": state, "reason": reason, "signed": signed, "psbt_signatures": psbt })
                    .to_string()
            }
            Err(e) => err(format!("fetch_result: {e}")),
        }
    }

    fn cancel(&mut self, handle: String) -> bool {
        let Some(receipt) = self.receipts.lock().unwrap().get(&handle).cloned() else {
            return false;
        };
        modules().signer_manager_module.cancel_approval(&handle, &receipt).unwrap_or(false)
    }

    fn unlock(&mut self, count: i64, confirm: bool) -> String {
        let terms = json!({ "account": ADDRESS, "password": VAULT_PASSWORD, "count": count,
                            "apps": ["evm_signer_cli_probe"], "confirm": confirm });
        match parse(modules().signer_manager_module.unlock(&terms.to_string())) {
            Ok(v) => v.to_string(),
            Err(e) => err(format!("unlock refused: {e}")),
        }
    }

    fn setup_bitcoin(&mut self) -> String {
        let p = json!({ "phrase": PHRASE, "family": "bitcoin", "chain": "test", "password": BTC_PASSWORD,
                        "label": "Regtest wallet" });
        match parse(modules().keystore_module.import_bitcoin(&p.to_string())) {
            Ok(v) => {
                // The account xpub, read off the receive descriptor: wpkh([fp/84'/1'/0']tpub…/0/*)#sum.
                let external = text(&v, "external");
                let xpub = external.split(']').nth(1).and_then(|r| r.split('/').next()).unwrap_or_default();
                let group = text(&v, "group");
                *self.bitcoin.lock().unwrap() = Some((group.clone(), xpub.to_string(), text(&v, "fingerprint")));
                json!({ "ok": true, "group": group }).to_string()
            }
            Err(e) => err(format!("import failed: {e}")),
        }
    }

    fn request_psbt(&mut self) -> String {
        let Some((group, xpub, fingerprint)) = self.bitcoin.lock().unwrap().clone() else {
            return err("no Bitcoin wallet yet: call setup_bitcoin first");
        };
        let psbt = match psbt_for(&xpub, &fingerprint) {
            Ok(p) => p,
            Err(e) => return err(format!("psbt: {e}")),
        };
        let intent = json!({ "group": group, "purpose": "Doc-test: a regtest send",
                             "legs": [{ "kind": "psbt", "network": "regtest", "psbt": psbt }] });
        match parse(modules().signer_manager_module.request_approval(&intent.to_string())) {
            Ok(v) => {
                let (handle, receipt) = (text(&v, "handle"), text(&v, "receipt"));
                self.receipts.lock().unwrap().insert(handle.clone(), receipt);
                json!({ "ok": true, "handle": handle }).to_string()
            }
            Err(e) => err(format!("request_approval refused: {e}")),
        }
    }

    fn unlock_bitcoin(&mut self, count: i64, confirm: bool) -> String {
        let Some((group, _, _)) = self.bitcoin.lock().unwrap().clone() else {
            return err("no Bitcoin wallet yet: call setup_bitcoin first");
        };
        let terms = json!({ "account": group, "password": BTC_PASSWORD, "count": count,
                            "apps": ["evm_signer_cli_probe"], "confirm": confirm });
        match parse(modules().signer_manager_module.unlock(&terms.to_string())) {
            Ok(v) => v.to_string(),
            Err(e) => err(format!("unlock refused: {e}")),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EvmSignerCliProbeModuleImpl>();
}
