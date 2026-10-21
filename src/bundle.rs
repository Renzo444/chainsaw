//! Detection rules and mappings that are embedded into the binary, so that hunting works out of
//! the box. They are extracted to a cache directory on first use, as the rule loaders work on
//! paths.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use include_dir::{Dir, include_dir};

static RULES: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules");
static SIGMA: Dir = include_dir!("$CARGO_MANIFEST_DIR/sigma");
static MAPPINGS: Dir = include_dir!("$CARGO_MANIFEST_DIR/mappings");

/// The mapping used to run the bundled Sigma rules against Windows event logs.
pub const SIGMA_MAPPING: &str = "sigma-event-logs-all.yml";

/// The location of the extracted bundle.
pub struct Bundle {
    pub root: PathBuf,
    pub rules: PathBuf,
    pub sigma: PathBuf,
    pub mapping: PathBuf,
}

fn bundles() -> [(&'static str, &'static Dir<'static>); 3] {
    [
        ("rules", &RULES),
        ("sigma", &SIGMA),
        ("mappings", &MAPPINGS),
    ]
}

fn files<'a>(dir: &'a Dir<'a>, out: &mut Vec<&'a include_dir::File<'a>>) {
    out.extend(dir.files());
    for dir in dir.dirs() {
        files(dir, out);
    }
}

/// Counts the embedded rule files, as (chainsaw, sigma).
pub fn counts() -> (usize, usize) {
    let count = |dir: &Dir| {
        let mut out = vec![];
        files(dir, &mut out);
        out.iter()
            .filter(|f| {
                f.path()
                    .extension()
                    .is_some_and(|e| e == "yml" || e == "yaml")
            })
            .count()
    };
    (count(&RULES), count(&SIGMA))
}

fn fingerprint() -> String {
    let mut hasher = DefaultHasher::new();
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    for (name, dir) in bundles() {
        let mut out = vec![];
        files(dir, &mut out);
        for file in out {
            name.hash(&mut hasher);
            file.path().hash(&mut hasher);
            file.contents().hash(&mut hasher);
        }
    }
    format!("{:016x}", hasher.finish())
}

fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CHAINSAW_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library").join("Caches"))
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("chainsaw")
}

/// Writes the embedded files into `dest`.
pub fn export(dest: &Path) -> crate::Result<()> {
    for (name, dir) in bundles() {
        let mut out = vec![];
        files(dir, &mut out);
        for file in out {
            let path = dest.join(name).join(file.path());
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, file.contents())?;
        }
    }
    Ok(())
}

/// Extracts the bundle to the cache directory, reusing a previous extraction of the same bundle.
pub fn extract() -> crate::Result<Bundle> {
    let cache = cache_dir();
    let root = cache.join(format!("bundle-{}", fingerprint()));
    let bundle = Bundle {
        rules: root.join("rules"),
        sigma: root.join("sigma"),
        mapping: root.join("mappings").join(SIGMA_MAPPING),
        root: root.clone(),
    };
    if root.join(".complete").exists() {
        return Ok(bundle);
    }
    fs::create_dir_all(&cache).map_err(|e| {
        anyhow!(
            "could not create cache directory '{}' - {} (set CHAINSAW_CACHE_DIR to override)",
            cache.display(),
            e
        )
    })?;
    // Extract into a scratch directory first so that concurrent runs never see a partial bundle.
    let scratch = cache.join(format!(
        ".bundle-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    export(&scratch)?;
    fs::write(scratch.join(".complete"), "")?;
    if fs::rename(&scratch, &root).is_err() {
        // Another process won the race.
        let _ = fs::remove_dir_all(&scratch);
        if !root.join(".complete").exists() {
            anyhow::bail!("could not extract bundled rules to '{}'", root.display());
        }
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_contains_rules_and_mapping() {
        let (chainsaw, sigma) = counts();
        assert!(chainsaw > 50, "chainsaw rules: {}", chainsaw);
        assert!(sigma > 1000, "sigma rules: {}", sigma);
        assert!(MAPPINGS.get_file(SIGMA_MAPPING).is_some());
    }

    #[test]
    fn extracts_once() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: tests that read this variable run in this test only.
        unsafe { std::env::set_var("CHAINSAW_CACHE_DIR", dir.path()) };
        let first = extract().unwrap();
        assert!(first.mapping.is_file());
        assert!(first.sigma.join("rules").join("windows").is_dir());
        let second = extract().unwrap();
        assert_eq!(first.root, second.root);
        unsafe { std::env::remove_var("CHAINSAW_CACHE_DIR") };
    }
}
