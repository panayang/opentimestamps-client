//! Local on-disk cache of timestamp upgrades, keyed by commitment digest.
//!
//! Mirrors `otsclient.cache.TimestampCache`: a directory sharded four levels
//! deep by the first four bytes of the commitment, so no directory ever
//! holds more than a few hundred thousand entries.

use crate::ots::serialize::{Reader, Writer};
use crate::ots::timestamp::Timestamp;
use std::path::{Path, PathBuf};

pub struct TimestampCache {
    path: Option<PathBuf>,
}

impl TimestampCache {
    pub fn new(path: Option<PathBuf>) -> std::io::Result<Self> {
        if let Some(p) = &path {
            let version_file = p.join("version");
            if !version_file.exists() {
                std::fs::create_dir_all(p)?;
                std::fs::write(&version_file, "1.0\n")?;
            }
        }
        Ok(Self { path })
    }

    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self { path: None }
    }

    fn commitment_to_path(&self, base: &Path, commitment: &[u8]) -> Option<PathBuf> {
        if commitment.len() < 4 || commitment.len() > 64 {
            return None;
        }
        let mut p = base.to_path_buf();
        for b in &commitment[0..4] {
            p.push(hex::encode([*b]));
        }
        p.push(hex::encode(commitment));
        Some(p)
    }

    pub fn get(&self, commitment: &[u8]) -> Option<Timestamp> {
        let base = self.path.as_ref()?;
        let path = self.commitment_to_path(base, commitment)?;
        let bytes = std::fs::read(path).ok()?;
        let mut r = Reader::new(&bytes);
        Timestamp::deserialize(&mut r, commitment.to_vec()).ok()
    }

    fn save(&self, timestamp: &Timestamp) -> std::io::Result<()> {
        let Some(base) = &self.path else {
            return Ok(());
        };
        let Some(path) = self.commitment_to_path(base, &timestamp.msg) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut w = Writer::new();
        // An empty timestamp (no ops/attestations yet) can't be serialized;
        // nothing useful to cache in that case.
        if timestamp.serialize(&mut w).is_ok() {
            std::fs::write(path, w.into_bytes())?;
        }
        Ok(())
    }

    /// Merge `new_timestamp` into whatever's cached for the same commitment,
    /// persisting the result.
    pub fn merge(&self, new_timestamp: &Timestamp) -> std::io::Result<()> {
        if self.path.is_none() {
            return Ok(());
        }
        let mut existing = self
            .get(&new_timestamp.msg)
            .unwrap_or_else(|| Timestamp::new(new_timestamp.msg.clone()));
        let _ = existing.merge(new_timestamp.clone());
        self.save(&existing)
    }
}
