//! signer_cli — the headless approver for `keystore_module`.

pub mod prompt;

#[cfg(feature = "logos_module")]
mod glue;
