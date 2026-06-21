//! Atomic marker file operations for the stalwart016 provisioner.
//!
//! The provisioner uses three tiers of marker files:
//!
//! - **Legacy** (`/var/lib/stalwart016/provisioned`): simple existence check.
//!   If present and migration marker is absent, the migration marker is
//!   auto-promoted from the legacy marker.
//!
//! - **Migration** (`/var/lib/stalwart016/migration-applied`): gates one-time
//!   migration inputs (the `export.json` from the 0.15→0.16 migration).
//!   Written once, never re-applied.
//!
//! - **Registry** (`/var/lib/stalwart016/registry-applied`): gates the
//!   generated plan. Content-addressed by the Nix store path of the plan
//!   file — if the store path changes (config changed), the plan is
//!   re-applied.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;

/// Content of a migration marker file.
#[derive(Debug, Clone)]
pub struct MigrationMarker {
    pub completed_at: String,
    pub migration_files: Vec<String>,
}

/// Content of a registry marker file.
#[derive(Debug, Clone)]
pub struct RegistryMarker {
    pub completed_at: String,
    pub generated_plan: String,
}

/// Check if a legacy marker exists (simple file-existence check).
#[allow(dead_code)]
pub fn has_legacy_marker(path: &Path) -> bool {
    path.exists()
}

/// Read a migration marker. Returns `Ok(None)` if the file doesn't exist.
pub fn read_migration_marker(path: &Path) -> Result<Option<MigrationMarker>> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("reading migration marker {}", path.display())),
    };

    let mut completed_at = String::new();
    let mut migration_files = Vec::new();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("completed_at=") {
            completed_at = val.to_string();
        } else if let Some(val) = line.strip_prefix("migration_files=") {
            migration_files = val.split_whitespace().map(String::from).collect();
        }
    }

    if completed_at.is_empty() {
        return Ok(None);
    }

    Ok(Some(MigrationMarker {
        completed_at,
        migration_files,
    }))
}

/// Read a registry marker. Returns `Ok(None)` if the file doesn't exist.
pub fn read_registry_marker(path: &Path) -> Result<Option<RegistryMarker>> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("reading registry marker {}", path.display())),
    };

    let mut completed_at = String::new();
    let mut generated_plan = String::new();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("completed_at=") {
            completed_at = val.to_string();
        } else if let Some(val) = line.strip_prefix("generated_plan=") {
            generated_plan = val.to_string();
        }
    }

    if completed_at.is_empty() || generated_plan.is_empty() {
        return Ok(None);
    }

    Ok(Some(RegistryMarker {
        completed_at,
        generated_plan,
    }))
}

/// Promote a legacy marker to a migration marker.
///
/// If the legacy marker exists and the migration marker does not, creates a
/// migration marker with the current timestamp and the legacy path noted.
/// This is a one-time upgrade path from the older single-marker scheme.
pub fn promote_legacy_marker(legacy_path: &Path, migration_path: &Path) -> Result<bool> {
    if !legacy_path.exists() || migration_path.exists() {
        return Ok(false);
    }

    let marker = MigrationMarker {
        completed_at: Utc::now().to_rfc3339(),
        migration_files: vec![format!("legacy_marker={}", legacy_path.display())],
    };
    write_migration_marker(migration_path, &marker)?;
    Ok(true)
}

/// Write a migration marker atomically.
///
/// Uses temp-file + fsync + rename to prevent partial reads on crash.
pub fn write_migration_marker(path: &Path, marker: &MigrationMarker) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    let content = format!(
        "completed_at={}\nmigration_files={}\n",
        marker.completed_at,
        marker.migration_files.join(" ")
    );

    atomic_write(&tmp_path, path, content.as_bytes())
}

/// Write a registry marker atomically.
///
/// Uses temp-file + fsync + rename to prevent partial reads on crash.
pub fn write_registry_marker(path: &Path, marker: &RegistryMarker) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    let content = format!(
        "completed_at={}\ngenerated_plan={}\n",
        marker.completed_at, marker.generated_plan
    );

    atomic_write(&tmp_path, path, content.as_bytes())
}

/// Atomic write: write to tmp_path, fsync, rename over dest.
///
/// Mode 0600 on the temp file, preserved after rename.
fn atomic_write(tmp_path: &Path, dest_path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp_path)
        .context(format!("creating temp file {}", tmp_path.display()))?;

    file.write_all(data)
        .context(format!("writing temp file {}", tmp_path.display()))?;

    file.sync_all()
        .context(format!("fsyncing temp file {}", tmp_path.display()))?;

    fs::rename(tmp_path, dest_path).context(format!(
        "renaming {} -> {}",
        tmp_path.display(),
        dest_path.display()
    ))?;

    // Re-verify mode after rename (rename preserves source mode on Linux,
    // but verify defensively).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(dest_path)
            .context(format!("reading metadata of {}", dest_path.display()))?
            .permissions();
        if perms.mode() & 0o777 != 0o600 {
            // Attempt to fix
            fs::set_permissions(dest_path, fs::Permissions::from_mode(0o600))
                .context(format!("chmod 0600 on {}", dest_path.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_migration_marker_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("migration-applied");

        let marker = MigrationMarker {
            completed_at: "2026-06-17T20:00:00+00:00".to_string(),
            migration_files: vec!["/nix/store/abc-export.json".to_string()],
        };

        write_migration_marker(&path, &marker).unwrap();

        let read = read_migration_marker(&path).unwrap().unwrap();
        assert_eq!(read.completed_at, marker.completed_at);
        assert_eq!(read.migration_files, marker.migration_files);
    }

    #[test]
    fn test_registry_marker_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry-applied");

        let marker = RegistryMarker {
            completed_at: "2026-06-17T20:00:00+00:00".to_string(),
            generated_plan: "/nix/store/abc123-stalwart016-apply.ndjson".to_string(),
        };

        write_registry_marker(&path, &marker).unwrap();

        let read = read_registry_marker(&path).unwrap().unwrap();
        assert_eq!(read.completed_at, marker.completed_at);
        assert_eq!(read.generated_plan, marker.generated_plan);
    }

    #[test]
    fn test_marker_missing_returns_none() {
        let dir = tempdir().unwrap();
        assert!(
            read_migration_marker(&dir.path().join("nope"))
                .unwrap()
                .is_none()
        );
        assert!(
            read_registry_marker(&dir.path().join("nope"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_legacy_promotion() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("provisioned");
        let migration = dir.path().join("migration-applied");

        // No legacy marker → no promotion
        assert!(!promote_legacy_marker(&legacy, &migration).unwrap());
        assert!(!migration.exists());

        // Create legacy marker
        fs::write(&legacy, "done").unwrap();

        // Legacy exists, migration doesn't → promote
        assert!(promote_legacy_marker(&legacy, &migration).unwrap());
        assert!(migration.exists());

        // Already promoted → no-op
        assert!(!promote_legacy_marker(&legacy, &migration).unwrap());
    }

    #[test]
    fn test_legacy_promotion_preserves_existing_migration() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("provisioned");
        let migration = dir.path().join("migration-applied");

        // Both exist → no promotion
        fs::write(&legacy, "done").unwrap();
        fs::write(&migration, "completed_at=already\nmigration_files=foo\n").unwrap();

        assert!(!promote_legacy_marker(&legacy, &migration).unwrap());

        // Migration content unchanged
        let content = fs::read_to_string(&migration).unwrap();
        assert!(content.contains("already"));
    }
}
