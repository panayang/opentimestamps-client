use crate::bitcoin::EsploraClient;
use crate::cache::TimestampCache;
use crate::calendar::UrlWhitelist;
use crate::cli::CommonOpts;
use crate::log::Logger;

pub struct Context {
    pub log: Logger,
    pub cache: TimestampCache,
    pub whitelist: UrlWhitelist,
    pub esplora: Option<EsploraClient>,
    pub wait: bool,
    pub wait_interval: u64,
}

impl Context {
    pub fn new(opts: &CommonOpts) -> anyhow::Result<Self> {
        let log = Logger::new(opts.verbose, opts.quiet);

        let cache_path = if opts.no_cache {
            None
        } else {
            Some(opts.cache.clone().unwrap_or_else(default_cache_dir))
        };
        let cache = TimestampCache::new(cache_path)?;

        let mut whitelist = if opts.no_default_whitelist {
            UrlWhitelist::new()
        } else {
            UrlWhitelist::with_defaults()
        };
        for url in &opts.whitelist {
            whitelist.add(url);
        }

        let esplora = if opts.no_bitcoin {
            None
        } else {
            Some(EsploraClient::new(opts.bitcoin_explorer.clone()))
        };

        Ok(Context {
            log,
            cache,
            whitelist,
            esplora,
            wait: opts.wait,
            wait_interval: opts.wait_interval,
        })
    }
}

fn default_cache_dir() -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("opentimestamps")
        .join("ots")
}
