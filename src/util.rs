use std::path::PathBuf;

/// Expand any shell-glob-looking arguments (useful on Windows, where the
/// shell doesn't expand globs itself). Plain paths pass through unchanged.
pub fn expand_globs(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        let s = p.to_string_lossy();
        if s.contains(['*', '?', '[']) {
            let mut matched = false;
            for entry in glob::glob(&s)? {
                out.push(entry?);
                matched = true;
            }
            if !matched {
                anyhow::bail!("no files matched pattern {s}");
            }
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}
