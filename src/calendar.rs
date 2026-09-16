//! HTTP client for OpenTimestamps remote calendar servers.
//!
//! Mirrors `opentimestamps.calendar.RemoteCalendar`: `POST /digest` to submit
//! a new commitment, `GET /timestamp/<hex>` to poll for an upgrade.

use crate::ots::serialize::Reader;
use crate::ots::timestamp::Timestamp;
use std::time::Duration;

pub const DEFAULT_CALENDAR_WHITELIST: &[&str] = &[
    "https://*.calendar.opentimestamps.org",
    "https://*.calendar.eternitywall.com",
    "https://*.calendar.catallaxy.com",
];

pub const DEFAULT_AGGREGATORS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

const MAX_RESPONSE_SIZE: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum CalendarError {
    #[error("commitment not found on calendar: {0}")]
    NotFound(String),
    #[error("calendar request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected response status {0} from calendar")]
    BadStatus(u16),
    #[error("calendar response exceeded size limit")]
    ResponseTooLarge,
    #[error(transparent)]
    Deser(#[from] crate::ots::serialize::DeserializeError),
    #[error(transparent)]
    Timestamp(#[from] crate::ots::timestamp::TimestampError),
}

pub struct RemoteCalendar {
    client: reqwest::Client,
    url: String,
    user_agent: String,
}

fn sanitize_response(bytes: &[u8]) -> String {
    const WHITELIST: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#-.,; ";
    bytes
        .iter()
        .take(160)
        .map(|&b| {
            if WHITELIST.contains(&b) {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

impl RemoteCalendar {
    pub fn new(url: impl Into<String>, user_agent: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.into(),
            user_agent: user_agent.into(),
        }
    }

    fn join(&self, path: &str) -> String {
        format!("{}/{}", self.url.trim_end_matches('/'), path)
    }

    pub async fn submit(
        &self,
        digest: &[u8],
        timeout: Duration,
    ) -> Result<Timestamp, CalendarError> {
        let resp = self
            .client
            .post(self.join("digest"))
            .header("Accept", "application/vnd.opentimestamps.v1")
            .header("User-Agent", &self.user_agent)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(digest.to_vec())
            .timeout(timeout)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(CalendarError::BadStatus(resp.status().as_u16()));
        }

        let bytes = resp.bytes().await?;
        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(CalendarError::ResponseTooLarge);
        }

        let mut r = Reader::new(&bytes);
        Ok(Timestamp::deserialize(&mut r, digest.to_vec())?)
    }

    pub async fn get_timestamp(
        &self,
        commitment: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Timestamp, CalendarError> {
        let mut req = self
            .client
            .get(self.join(&format!("timestamp/{}", hex::encode(commitment))))
            .header("Accept", "application/vnd.opentimestamps.v1")
            .header("User-Agent", &self.user_agent);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }

        let resp = req.send().await?;
        let status = resp.status();

        if status.as_u16() == 404 {
            let bytes = resp.bytes().await.unwrap_or_default();
            return Err(CalendarError::NotFound(sanitize_response(&bytes)));
        }
        if !status.is_success() {
            return Err(CalendarError::BadStatus(status.as_u16()));
        }

        let bytes = resp.bytes().await?;
        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(CalendarError::ResponseTooLarge);
        }

        let mut r = Reader::new(&bytes);
        Ok(Timestamp::deserialize(&mut r, commitment.to_vec())?)
    }
}

/// Glob-style URL whitelist, matching `opentimestamps.calendar.UrlWhitelist`
/// closely enough for our purposes: scheme + host glob + exact path.
pub struct UrlWhitelist {
    patterns: Vec<String>,
}

impl UrlWhitelist {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut w = Self::new();
        for p in DEFAULT_CALENDAR_WHITELIST {
            w.add(p);
        }
        w
    }

    pub fn add(&mut self, url: &str) {
        self.patterns.push(url.to_string());
    }

    pub fn contains(&self, url: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| glob_match_url(pattern, url))
    }
}

fn split_url(s: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = s.split_once("://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    Some((scheme, host, path))
}

fn glob_match_url(pattern: &str, url: &str) -> bool {
    // Split into scheme://host/path and glob-match the host component only,
    // matching the Python implementation's use of fnmatch on netloc.
    match (split_url(pattern), split_url(url)) {
        (Some((ps, ph, pp)), Some((us, uh, up))) => {
            ps == us
                && pp == up
                && glob::Pattern::new(ph)
                    .map(|g| g.matches(uh))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

impl Default for UrlWhitelist {
    fn default() -> Self {
        Self::new()
    }
}
