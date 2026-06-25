//! Bitcoin block header verification.
//!
//! The original Python client requires a local `bitcoind` with RPC access
//! just to verify a merkle root against a block header — a heavy dependency
//! for what is fundamentally a public-data lookup. This client instead talks
//! to an Esplora-compatible REST API (mempool.space / blockstream.info, or a
//! self-hosted instance), which needs no node and no credentials.

use serde::Deserialize;
use std::time::Duration;

#[allow(dead_code)]
pub const DEFAULT_ESPLORA_URL: &str = "https://mempool.space/api";

#[derive(Debug, thiserror::Error)]
pub enum BitcoinError {
    #[error("request to block explorer failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("block height {height} not found; chain tip is at {tip}")]
    HeightNotFound { height: u64, tip: u64 },
    #[error("invalid hex in explorer response: {0}")]
    BadHex(#[from] hex::FromHexError),
    #[error("digest must be 32 bytes, got {0}")]
    BadDigestLength(usize),
    #[error("merkle root mismatch: attestation does not match block {0}")]
    MerkleMismatch(u64),
}

#[derive(Debug, Deserialize)]
struct BlockHeaderJson {
    height: u64,
    timestamp: u64,
    merkle_root: String,
}

pub struct EsploraClient {
    client: reqwest::Client,
    base_url: String,
}

/// Result of successfully checking a Bitcoin attestation against a real block.
pub struct VerifiedAttestation {
    #[allow(dead_code)]
    pub height: u64,
    /// Unix timestamp of the block, per its header.
    pub block_time: u64,
}

impl EsploraClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
            base_url: base_url.into(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path)
    }

    pub async fn tip_height(&self) -> Result<u64, BitcoinError> {
        let txt = self
            .client
            .get(self.url("blocks/tip/height"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(txt.trim().parse().unwrap_or(0))
    }

    async fn block_hash_at_height(&self, height: u64) -> Result<String, BitcoinError> {
        let resp = self
            .client
            .get(self.url(&format!("block-height/{height}")))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let tip = self.tip_height().await.unwrap_or(0);
            return Err(BitcoinError::HeightNotFound { height, tip });
        }
        Ok(resp.error_for_status()?.text().await?.trim().to_string())
    }

    async fn block_header(&self, hash: &str) -> Result<BlockHeaderJson, BitcoinError> {
        let resp = self
            .client
            .get(self.url(&format!("block/{hash}")))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Verify that `digest` (the OTS attestation's message, in internal byte
    /// order) equals the merkle root of the block at `height`. Returns the
    /// block's timestamp on success.
    pub async fn verify_merkle_root(
        &self,
        digest: &[u8],
        height: u64,
    ) -> Result<VerifiedAttestation, BitcoinError> {
        if digest.len() != 32 {
            return Err(BitcoinError::BadDigestLength(digest.len()));
        }

        let hash = self.block_hash_at_height(height).await?;
        let header = self.block_header(&hash).await?;

        // Esplora reports merkle_root in display (big-endian/reversed) hex;
        // OTS digests use internal (raw, little-endian) byte order.
        let mut merkle_root_internal = hex::decode(&header.merkle_root)?;
        merkle_root_internal.reverse();

        if merkle_root_internal != digest {
            return Err(BitcoinError::MerkleMismatch(height));
        }

        Ok(VerifiedAttestation {
            height: header.height,
            block_time: header.timestamp,
        })
    }
}
