//! evm_signer_cli — the headless approver for `signer_manager_module`.

pub mod decoder;
pub mod prompt;
pub mod tokenlist;

#[cfg(feature = "logos_module")]
mod glue;
