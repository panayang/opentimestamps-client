//! Shared timestamp-completion logic: submitting new commitments to
//! calendars, and upgrading pending attestations to verifiable ones.
//!
//! Ported from `otsclient.cmds.create_timestamp` / `upgrade_timestamp`.

use crate::cache::TimestampCache;
use crate::calendar::{CalendarError, RemoteCalendar, UrlWhitelist};
use crate::ots::notary::TimeAttestation;
use crate::ots::timestamp::Timestamp;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::Instant;

pub fn user_agent() -> String {
    format!("ots-client-rs/{}", env!("CARGO_PKG_VERSION"))
}

pub fn is_timestamp_complete(stamp: &Timestamp) -> bool {
    stamp
        .all_attestations()
        .iter()
        .any(|(_, a)| matches!(a, TimeAttestation::Bitcoin { .. }))
}

fn all_attestation_set(stamp: &Timestamp) -> HashSet<TimeAttestation> {
    let mut set = HashSet::new();
    fn walk(stamp: &Timestamp, set: &mut HashSet<TimeAttestation>) {
        for a in &stamp.attestations {
            set.insert(a.clone());
        }
        for child in stamp.ops.values() {
            walk(child, set);
        }
    }
    walk(stamp, &mut set);
    set
}

/// Submit `tip` (a freshly built commitment) to `m`-of-`calendar_urls`
/// calendars concurrently, merging in whichever respond before `timeout`.
pub async fn create_timestamp(
    tip: &mut Timestamp,
    calendar_urls: &[String],
    m: usize,
    timeout: Duration,
    on_log: impl Fn(&str),
) -> anyhow::Result<()> {
    let n = calendar_urls.len();
    if m == 0 || m > n {
        anyhow::bail!(
            "m ({m}) cannot be greater than available calendar(s) ({n}), nor <= 0"
        );
    }

    let deadline = Instant::now() + timeout;
    let mut futs = FuturesUnordered::new();
    for url in calendar_urls {
        let cal = RemoteCalendar::new(url.clone(), user_agent());
        let digest = tip.msg.clone();
        let url = url.clone();
        on_log(&format!("Submitting to remote calendar {url}"));
        futs.push(async move {
            let r = cal.submit(&digest, timeout).await;
            (url, r)
        });
    }

    let mut merged = 0usize;
    while merged < m {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, futs.next()).await {
            Ok(Some((_url, Ok(ts)))) => {
                tip.merge(ts)?;
                merged += 1;
            }
            Ok(Some((url, Err(e)))) => {
                on_log(&format!("Calendar {url} failed: {e}"));
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    if merged < m {
        anyhow::bail!(
            "failed to create timestamp: need at least {m} attestation(s) but received {merged} within timeout"
        );
    }
    Ok(())
}

/// Merge in any cached upgrades for every node in the tree (recursing into
/// newly-merged-in children too, matching the Python implementation).
pub fn merge_cache_pass(stamp: &mut Timestamp, cache: &TimestampCache) {
    if let Some(cached) = cache.get(&stamp.msg) {
        let _ = stamp.merge(cached);
    }
    for child in stamp.ops.values_mut() {
        merge_cache_pass(child, cache);
    }
}

/// Nodes that are the first attestation-bearing ancestor along each path -
/// i.e. nodes whose `PendingAttestation`s are worth checking for upgrades.
fn directly_verified<'a>(stamp: &'a Timestamp, out: &mut Vec<&'a Timestamp>) {
    if !stamp.attestations.is_empty() {
        out.push(stamp);
    } else {
        for child in stamp.ops.values() {
            directly_verified(child, out);
        }
    }
}

fn merge_into_matching(stamp: &mut Timestamp, target: &[u8], ts: &Timestamp) {
    if stamp.msg == target {
        let _ = stamp.merge(ts.clone());
    }
    for child in stamp.ops.values_mut() {
        merge_into_matching(child, target, ts);
    }
}

/// Attempt to upgrade `timestamp` so it becomes independently verifiable.
///
/// Returns `true` if anything changed (false means it was already complete,
/// or no calendar had anything new to offer).
pub async fn upgrade_timestamp(
    timestamp: &mut Timestamp,
    calendar_urls: &[String],
    whitelist: &UrlWhitelist,
    cache: &TimestampCache,
    wait: bool,
    wait_interval: u64,
    on_log: impl Fn(&str),
) -> bool {
    let before_cache = all_attestation_set(timestamp);
    merge_cache_pass(timestamp, cache);
    let mut changed = all_attestation_set(timestamp).len() > before_cache.len();
    if changed {
        on_log("Got attestation(s) from local cache");
    }

    loop {
        if is_timestamp_complete(timestamp) {
            break;
        }

        let mut targets: Vec<(Vec<u8>, String)> = Vec::new();
        {
            let mut nodes = Vec::new();
            directly_verified(timestamp, &mut nodes);
            for node in nodes {
                for att in &node.attestations {
                    if let TimeAttestation::Pending { uri } = att {
                        let urls: Vec<String> = if !calendar_urls.is_empty() {
                            calendar_urls.to_vec()
                        } else if whitelist.contains(uri) {
                            vec![uri.clone()]
                        } else {
                            on_log(&format!(
                                "Ignoring attestation from calendar {uri}: not in whitelist"
                            ));
                            continue;
                        };
                        for u in urls {
                            targets.push((node.msg.clone(), u));
                        }
                    }
                }
            }
        }

        let before = all_attestation_set(timestamp);

        let mut futs = FuturesUnordered::new();
        for (commitment, url) in targets {
            let cal = RemoteCalendar::new(url.clone(), user_agent());
            futs.push(async move {
                let r = cal.get_timestamp(&commitment, Some(Duration::from_secs(15))).await;
                (commitment, url, r)
            });
        }

        while let Some((commitment, url, result)) = futs.next().await {
            match result {
                Ok(ts) => {
                    let _ = cache.merge(&ts);
                    merge_into_matching(timestamp, &commitment, &ts);
                }
                Err(CalendarError::NotFound(reason)) => {
                    on_log(&format!("Calendar {url}: {reason}"));
                }
                Err(e) => {
                    on_log(&format!("Calendar {url}: {e}"));
                }
            }
        }

        let after = all_attestation_set(timestamp);
        let found_new = after.len() > before.len();
        if found_new {
            on_log(&format!(
                "Got {} new attestation(s)",
                after.len() - before.len()
            ));
            changed = true;
        }

        if !wait {
            break;
        } else if found_new {
            continue;
        } else {
            on_log(&format!(
                "Timestamp not complete; waiting {wait_interval}s before trying again"
            ));
            tokio::time::sleep(Duration::from_secs(wait_interval)).await;
        }
    }

    changed
}
