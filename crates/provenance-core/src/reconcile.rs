//! Reconcile primitives shared by the reconcilers.

/// Outcome tally for a reconcile pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
}
