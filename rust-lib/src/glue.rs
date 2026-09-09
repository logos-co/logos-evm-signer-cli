//! Logos glue for `evm_signer_cli`: a Tier A approver that shows each request over the
//! event plane and takes the decision over method calls.
//!
//! One worker thread owns every keystore-facing sequence through `lane`; `state` is
//! held only for reads and writes, never across a call, so `status()` always answers.

use crate::prompt::{configure_hint, holds, normalise_bundle_id, render, scrub, strip_file_newline, Rendered};
use serde_json::{json, Value};
use std::time::Duration;

const ME: &str = "evm_signer_cli";
const POLL: Duration = Duration::from_secs(1);
const KS_TIMEOUT: Duration = Duration::from_secs(5);
/// Scrypt runs inside the keystore's `approve`; the spec asks for a deadline well above it.
const APPROVE_TIMEOUT: Duration = Duration::from_secs(60);

pub trait EvmSignerCliModule: Send + Sync + 'static {
    /// `{ ok, held, identity, approvers, custodians, rendered, pending_count, last_error, hint }`.
    fn status(&self) -> String;
    /// The keystore's queue summaries — never leg detail.
    fn list(&self) -> String;
    /// Claim `handle` for display: the keystore's lines, verbatim, plus the prompt text.
    fn show(&self, handle: String) -> String;
    /// The human said yes to the request on screen. `bundle_id` must be the value shown.
    fn approve(&self, handle: String, bundle_id: String, password: String) -> String;
    /// The human said no.
    fn reject(&self, handle: String) -> bool;
    /// Re-read the queue now, then answer as `status` does.
    fn refresh(&self) -> String;
    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait EvmSignerCliModuleEvents {
    /// A request is on screen. `text` is the whole block a human reads.
    fn prompt(&self, handle: String, text: String);
    /// `approved` | `rejected` from the keystore; `gone` when the poll finds it vanished.
    fn settled(&self, handle: String, state: String);
    fn queue_changed(&self, count: i64);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct State {
    rendered: Option<Rendered>,
    queue: Vec<Value>,
    last_error: Option<String>,
}

#[derive(Default)]
struct Inner {
    lane: std::sync::Mutex<()>,
    state: std::sync::Mutex<State>,
    started: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct EvmSignerCliModuleImpl {
    inner: std::sync::Arc<Inner>,
}

fn err(msg: impl Into<String>) -> String {
    json!({ "ok": false, "error": msg.into() }).to_string()
}

fn parse(reply: Result<String, impl std::fmt::Debug>) -> Result<Value, String> {
    let raw = reply.map_err(|e| format!("keystore unreachable: {e:?}"))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v)
    } else {
        Err(v.get("error").and_then(Value::as_str).unwrap_or("call refused").to_string())
    }
}

fn identity() -> Value {
    modules()
        .keystore_module
        .caller_identity()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn summaries() -> Result<Vec<Value>, String> {
    let v = parse(modules().keystore_module.pending_with_timeout(KS_TIMEOUT))?;
    Ok(v.get("pending").and_then(Value::as_array).cloned().unwrap_or_default())
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn claim(handle: &str) -> Result<Rendered, String> {
    let v = parse(modules().keystore_module.acknowledge_with_timeout(handle, KS_TIMEOUT))?;
    let field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    Ok(Rendered {
        handle: field("handle"),
        bundle_id: field("bundle_id"),
        requester: field("requester"),
        claim_lines: strings(&v, "claim_lines"),
        render_lines: strings(&v, "render_lines"),
    })
}

fn handle_of(summary: &Value) -> Option<&str> {
    summary.get("handle").and_then(Value::as_str)
}

impl Inner {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Caller holds `lane`.
    fn reconcile(&self) {
        let queue = match summaries() {
            Ok(q) => q,
            Err(e) => {
                self.lock_state().last_error = Some(e);
                return;
            }
        };
        let (count_moved, gone, pick) = {
            let mut st = self.lock_state();
            st.last_error = None;
            let count_moved = st.queue.len() != queue.len();
            let gone = match &st.rendered {
                Some(r) if !queue.iter().any(|s| handle_of(s) == Some(&r.handle)) => Some(r.handle.clone()),
                _ => None,
            };
            if gone.is_some() {
                st.rendered = None;
            }
            // Prefer what another approver already has on screen, so two of us converge.
            let pick = match st.rendered {
                None => queue
                    .iter()
                    .find(|s| s.get("state").and_then(Value::as_str) == Some("rendered"))
                    .or(queue.first())
                    .and_then(handle_of)
                    .map(str::to_string),
                Some(_) => None,
            };
            st.queue = queue;
            (count_moved, gone, pick)
        };
        if count_moved {
            emit_queue_changed(self.lock_state().queue.len() as i64);
        }
        if let Some(h) = gone {
            emit_settled(&h, "gone");
        }
        if let Some(h) = pick {
            match claim(&h) {
                Ok(r) => self.put_on_screen(r),
                Err(e) => self.lock_state().last_error = Some(e),
            }
        }
    }

    fn put_on_screen(&self, r: Rendered) {
        let text = render(&r);
        let handle = r.handle.clone();
        self.lock_state().rendered = Some(r);
        emit_prompt(&handle, &text);
    }

    /// Drop `handle` locally; true if it was known here (rendered or queued).
    fn forget(&self, handle: &str) -> bool {
        let mut st = self.lock_state();
        let shown = st.rendered.as_ref().is_some_and(|r| r.handle == handle);
        let before = st.queue.len();
        st.queue.retain(|s| handle_of(s) != Some(handle));
        if shown {
            st.rendered = None;
        }
        shown || st.queue.len() != before
    }

    fn on_settled(&self, handle: &str, state: &str) {
        if self.forget(handle) {
            emit_settled(handle, state);
        }
    }

    fn run(&self) {
        let mut offered = None;
        let mut settled = None;
        loop {
            if offered.is_none() {
                offered = modules().keystore_module.on_approval_offered().ok();
            }
            if settled.is_none() {
                settled = modules().keystore_module.on_approval_settled().ok();
            }
            if let Some(s) = &settled {
                while let Ok(ev) = s.try_recv() {
                    for e in keystore_module::KeystoreModuleClient::decode_approval_settled(&ev) {
                        self.on_settled(&e.handle, &e.state);
                    }
                }
            }
            {
                let _lane = self.lane.lock().unwrap_or_else(|p| p.into_inner());
                self.reconcile();
            }
            match &offered {
                Some(s) => {
                    let _ = s.receiver().recv_timeout(POLL);
                }
                None => std::thread::sleep(POLL),
            }
        }
    }
}

impl EvmSignerCliModuleImpl {
    fn status_json(&self) -> String {
        let id = identity();
        let held = holds(&id, ME, "approvers");
        let st = self.inner.lock_state();
        json!({
            "ok": true,
            "held": held,
            "identity": id.get("identity").cloned().unwrap_or(Value::Null),
            "approvers": id.get("approvers").cloned().unwrap_or(json!([])),
            "custodians": id.get("custodians").cloned().unwrap_or(json!([])),
            "rendered": st.rendered.as_ref().map(|r| json!({
                "handle": r.handle, "bundle_id": r.bundle_id, "requester": r.requester,
            })),
            "pending_count": st.queue.len(),
            "last_error": st.last_error.as_deref().filter(|e| !(held && *e == "not authorized")),
            "hint": if held { Value::Null } else { Value::String(configure_hint(&id, ME, "approvers")) },
        })
        .to_string()
    }
}

impl EvmSignerCliModule for EvmSignerCliModuleImpl {
    fn on_context_ready(&self, _ctx: &RustModuleContext) {
        if self.inner.started.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let inner = std::sync::Arc::clone(&self.inner);
        std::thread::spawn(move || inner.run());
    }

    fn status(&self) -> String {
        self.status_json()
    }

    fn list(&self) -> String {
        match summaries() {
            Ok(q) => json!({ "ok": true, "pending": q }).to_string(),
            Err(e) => err(e),
        }
    }

    fn show(&self, handle: String) -> String {
        let _lane = self.inner.lane.lock().unwrap_or_else(|p| p.into_inner());
        match claim(handle.trim()) {
            Ok(r) => {
                let text = render(&r);
                let reply = json!({
                    "ok": true, "handle": r.handle, "bundle_id": r.bundle_id, "requester": r.requester,
                    "claim_lines": r.claim_lines, "render_lines": r.render_lines, "text": text,
                });
                self.inner.put_on_screen(r);
                reply.to_string()
            }
            Err(e) => err(e),
        }
    }

    fn approve(&self, handle: String, bundle_id: String, mut password: String) -> String {
        let handle = handle.trim().to_string();
        let wanted = normalise_bundle_id(&bundle_id);
        let _lane = self.inner.lane.lock().unwrap_or_else(|p| p.into_inner());

        let refuse = |password: &mut String, msg: &str| {
            scrub(password);
            err(msg)
        };
        let shown = self.inner.lock_state().rendered.clone();
        match shown {
            Some(r) if r.handle == handle => {
                if normalise_bundle_id(&r.bundle_id) != wanted {
                    return refuse(&mut password, "bundle_id does not match the request on screen");
                }
            }
            _ => return refuse(&mut password, "that is not the request on screen; run `show <handle>` first"),
        }
        // Re-claim: another approver may have demoted it, and a settled record refuses here,
        // before the password is used. The commitment is deterministic, so the id must hold.
        let fresh = match claim(&handle) {
            Ok(r) => r,
            Err(e) => return refuse(&mut password, &format!("could not re-open the request: {e}")),
        };
        if normalise_bundle_id(&fresh.bundle_id) != wanted {
            return refuse(&mut password, "bundle_id does not match the request on screen");
        }

        let out = modules().keystore_module.approve_with_timeout(
            &handle,
            &fresh.bundle_id,
            strip_file_newline(&password),
            APPROVE_TIMEOUT,
        );
        scrub(&mut password);
        match parse(out) {
            Ok(v) => {
                self.inner.forget(&handle);
                emit_settled(&handle, "approved");
                json!({ "ok": true, "handle": handle, "signed_count": v.get("signed_count").cloned().unwrap_or(Value::Null) })
                    .to_string()
            }
            Err(_) => err("approval failed: wrong password, or the request is no longer the one being rendered"),
        }
    }

    fn reject(&self, handle: String) -> bool {
        let handle = handle.trim().to_string();
        let _lane = self.inner.lane.lock().unwrap_or_else(|p| p.into_inner());
        let ok = modules().keystore_module.reject(&handle).unwrap_or(false);
        if ok {
            self.inner.forget(&handle);
            emit_settled(&handle, "rejected");
        }
        ok
    }

    fn refresh(&self) -> String {
        {
            let _lane = self.inner.lane.lock().unwrap_or_else(|p| p.into_inner());
            self.inner.reconcile();
        }
        self.status_json()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EvmSignerCliModuleImpl>();
}
