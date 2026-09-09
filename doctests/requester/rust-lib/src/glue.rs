//! The requester half of the signer_cli doc-test. It can ASK and can never APPROVE:
//! every signature it reports exists because a human typed `logosctl call signer_cli
//! approve …`. Method-driven, so the spec controls every step.

use serde_json::{json, Value};

type Receipts = std::sync::Mutex<std::collections::HashMap<String, String>>;

/// Foundry's well-known account 0. A published test key: never fund it.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VAULT_PASSWORD: &str = "doctest-pw";

pub trait SignerCliProbeModule: Send + 'static {
    /// Import the test key (Tier D — this fixture must be the custodian). `{ ok, address }`.
    fn setup(&mut self) -> String;
    /// Ask for a signature over `message`. `{ ok, handle }`; the receipt stays here.
    fn request(&mut self, message: String) -> String;
    /// `{ ok, state, reason?, signed? }` — collects and acknowledges the result once approved.
    fn outcome(&mut self, handle: String) -> String;
    /// Give up on a request, the one ending the keystore never announces.
    fn cancel(&mut self, handle: String) -> bool;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct SignerCliProbeModuleImpl {
    receipts: Receipts,
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

impl SignerCliProbeModule for SignerCliProbeModuleImpl {
    fn setup(&mut self) -> String {
        match parse(modules().keystore_module.import_private_key(TEST_KEY, VAULT_PASSWORD)) {
            Ok(v) => json!({ "ok": true, "address": text(&v, "address") }).to_string(),
            Err(e) => err(format!("import failed: {e}")),
        }
    }

    fn request(&mut self, message: String) -> String {
        let intent = json!({
            "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
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
        match parse(modules().keystore_module.request_approval(&intent.to_string())) {
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
        let status = match parse(modules().keystore_module.approval_status(&handle, &receipt)) {
            Ok(v) => v,
            Err(e) => return err(format!("approval_status: {e}")),
        };
        let (state, reason) = (text(&status, "state"), text(&status, "reason"));
        if reason != "approved" {
            return json!({ "ok": true, "state": state, "reason": reason }).to_string();
        }
        match parse(modules().keystore_module.fetch_result(&handle, &receipt)) {
            Ok(v) => {
                let signed = v.get("signed").cloned().unwrap_or(Value::Null);
                let _ = modules().keystore_module.ack_result(&handle, &receipt);
                json!({ "ok": true, "state": state, "reason": reason, "signed": signed }).to_string()
            }
            Err(e) => err(format!("fetch_result: {e}")),
        }
    }

    fn cancel(&mut self, handle: String) -> bool {
        let Some(receipt) = self.receipts.lock().unwrap().get(&handle).cloned() else {
            return false;
        };
        modules().keystore_module.cancel_approval(&handle, &receipt).unwrap_or(false)
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<SignerCliProbeModuleImpl>();
}
