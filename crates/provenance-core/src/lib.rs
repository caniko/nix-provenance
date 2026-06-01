//! Shared plumbing for `nix-provenance` reconcilers.
//!
//! Licensed `MIT OR Apache-2.0` so it can be consumed by BOTH the AGPL
//! `immich-provision` crate and the `MIT OR Apache-2.0` `rauthy-provision`
//! crate (permissive code can be linked by either; the reverse is not true).
//! Keep this crate generic — HTTP / secret / serde / set / reconcile primitives
//! only, never service-specific request-building or reconcile bodies. Any helper
//! that originated in the AGPL immich crate is clean-reimplemented here, never
//! copied, so no AGPL source text is relicensed.

pub mod http;
pub mod reconcile;
pub mod secret;
pub mod serde_ext;
pub mod setops;
