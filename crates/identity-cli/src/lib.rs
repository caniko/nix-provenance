//! Library surface for the `identity-cli` provisioning commands.

#[cfg(feature = "bitwarden")]
pub mod bitwarden;

#[cfg(feature = "kanidm")]
pub mod kanidm;
