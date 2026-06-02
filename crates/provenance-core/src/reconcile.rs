//! Reconcile primitives shared by the reconcilers.

/// Outcome tally for a reconcile pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Summary {
    /// Number of entities created because they were present in desired state
    /// but absent from the remote system.
    pub created: usize,
    /// Number of existing entities updated because managed fields drifted.
    pub updated: usize,
    /// Number of existing entities deleted because desired state marked them
    /// absent and deletion was allowed.
    pub deleted: usize,
    /// Number of entities left unchanged because remote state already matched
    /// the desired managed fields.
    pub unchanged: usize,
}
