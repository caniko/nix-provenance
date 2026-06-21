//! Order-insensitive string-set helpers used by additive reconciliation.

/// `None` for an empty slice, else an owned copy — lets callers omit empty
/// optional list fields from a request body.
#[must_use]
pub fn opt_vec(v: &[String]) -> Option<Vec<String>> {
    if v.is_empty() { None } else { Some(v.to_vec()) }
}

/// Order-insensitive equality of two string collections.
#[must_use]
pub fn same_set(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut a: Vec<&String> = a.iter().collect();
    let mut b: Vec<&String> = b.iter().collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

/// True when every element of `needle` is present in `haystack`.
#[must_use]
pub fn is_subset(needle: &[String], haystack: &[String]) -> bool {
    needle.iter().all(|n| haystack.contains(n))
}

/// `current` plus any of `wanted` not already present, original order preserved.
/// The basis of additive reconciliation: declared roles/groups are merged in,
/// out-of-band ones are never stripped.
#[must_use]
pub fn union(current: &[String], wanted: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(current.len() + wanted.len());
    out.extend_from_slice(current);
    for w in wanted {
        if !out.contains(w) {
            out.push(w.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn same_set_is_order_insensitive() {
        assert!(same_set(&v(&["a", "b"]), &v(&["b", "a"])));
        assert!(!same_set(&v(&["a"]), &v(&["a", "b"])));
    }

    #[test]
    fn union_preserves_order_and_dedups() {
        assert_eq!(union(&v(&["a"]), &v(&["a", "b"])), v(&["a", "b"]));
    }

    #[test]
    fn subset_checks_membership() {
        assert!(is_subset(&v(&["a"]), &v(&["a", "b"])));
        assert!(!is_subset(&v(&["c"]), &v(&["a", "b"])));
    }

    #[test]
    fn opt_vec_empty_is_none() {
        assert!(opt_vec(&[]).is_none());
        assert_eq!(opt_vec(&v(&["x"])), Some(v(&["x"])));
    }
}
