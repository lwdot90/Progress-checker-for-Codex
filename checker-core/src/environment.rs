//! Process-local RPM inventory caching. Source fingerprints are never cached.
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    name: String,
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn stamp(path: &Path) -> Result<Stamp, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    Ok(Stamp {
        name: path.to_string_lossy().into_owned(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    })
}
fn database_key(directory: &Path) -> Result<Vec<Stamp>, String> {
    let directory = directory.canonicalize().map_err(|e| e.to_string())?;
    let mut paths = fs::read_dir(&directory)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    // SQLite shared-memory bookkeeping and the lock file do not contain package
    // data. Queries themselves modify shared memory. Main DB and WAL are watched.
    paths.retain(|path| {
        !matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("rpmdb.sqlite-shm" | ".rpm.lock")
        )
    });
    paths.sort();
    if paths.is_empty() || paths.len() > 128 {
        return Err("unsupported RPM database layout".into());
    }
    let mut key = vec![stamp(&directory)?, stamp(Path::new("/usr/bin/rpm"))?];
    for path in paths {
        key.push(stamp(&path)?);
    }
    Ok(key)
}
#[derive(Default)]
struct Cache {
    value: Option<(Vec<Stamp>, Vec<u8>)>,
}
impl Cache {
    fn inventory(
        &mut self,
        directory: &Path,
        collect: impl FnOnce(&Path) -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        let before = match database_key(directory) {
            Ok(key) => key,
            Err(error) => {
                self.value = None;
                return Err(error);
            }
        };
        if let Some((key, bytes)) = &self.value
            && *key == before
            && database_key(directory).is_ok_and(|key| key == before)
        {
            return Ok(bytes.clone());
        }
        self.value = None;
        let bytes = collect(directory)?;
        if database_key(directory)? != before {
            return Err("package environment changed while inspecting inventory".into());
        }
        self.value = Some((before, bytes.clone()));
        Ok(bytes)
    }
}
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

pub fn package_inventory() -> Result<Vec<u8>, String> {
    #[cfg(test)]
    if let Some(result) = TEST_INVENTORY.with(|provider| {
        provider.borrow_mut().as_mut().map(|provider| {
            provider
                .cache
                .inventory(&provider.directory, collect_inventory)
        })
    }) {
        return result;
    }
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .map_err(|_| "environment cache unavailable")?;
    cache.inventory(Path::new("/usr/lib/sysimage/rpm"), collect_inventory)
}
fn collect_inventory(directory: &Path) -> Result<Vec<u8>, String> {
    let output = tempfile::tempfile().map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new("/usr/bin/rpm")
        .env_clear()
        .arg("--dbpath")
        .arg(directory)
        .args([
            "-qa",
            "--qf",
            "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdout(output.try_clone().map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    loop {
        if output.metadata().map_err(|e| e.to_string())?.len() > 8 * 1024 * 1024
            || started.elapsed() > Duration::from_secs(30)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("verification environment inventory exceeds time or size limit".into());
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            if !status.success() {
                return Err("verification environment unavailable".into());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut output = output;
    output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    output
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("environment inventory exceeds limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
struct TestInventory {
    directory: std::path::PathBuf,
    cache: Cache,
}
#[cfg(test)]
thread_local! {
    static TEST_INVENTORY: std::cell::RefCell<Option<TestInventory>> = const {
        std::cell::RefCell::new(None)
    };
}

/// A scoped, thread-local fixture exists only in unit-test builds. Production
/// has no environment variable, config field, or API for changing host paths.
#[cfg(test)]
pub(crate) fn with_test_inventory<T>(directory: &Path, task: impl FnOnce() -> T) -> T {
    struct Restore(Option<TestInventory>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_INVENTORY.with(|provider| {
                provider.replace(self.0.take());
            });
        }
    }
    let previous = TEST_INVENTORY.with(|provider| {
        provider.replace(Some(TestInventory {
            directory: directory.to_owned(),
            cache: Cache::default(),
        }))
    });
    let _restore = Restore(previous);
    task()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stamp_detects_same_length_rewrite_and_atomic_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database");
        fs::write(&path, "before").unwrap();
        let before = stamp(&path).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&path, "after!").unwrap();
        assert_ne!(before, stamp(&path).unwrap());
        let rewritten = stamp(&path).unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, "after!").unwrap();
        fs::rename(replacement, &path).unwrap();
        assert_ne!(rewritten, stamp(&path).unwrap());
    }

    #[test]
    fn inventory_cache_hits_recollects_after_change_and_drops_failed_values() {
        use std::cell::Cell;
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("rpmdb.sqlite");
        fs::write(&database, "before").unwrap();
        let collections = Cell::new(0);
        let collect = |directory: &Path| {
            collections.set(collections.get() + 1);
            fs::read(directory.join("rpmdb.sqlite")).map_err(|e| e.to_string())
        };
        let mut cache = Cache::default();
        assert_eq!(
            cache.inventory(directory.path(), collect).unwrap(),
            b"before"
        );
        assert_eq!(
            cache.inventory(directory.path(), collect).unwrap(),
            b"before"
        );
        assert_eq!(collections.get(), 1, "warm read must not recollect");
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&database, "after!").unwrap();
        assert_eq!(
            cache.inventory(directory.path(), collect).unwrap(),
            b"after!"
        );
        assert_eq!(collections.get(), 2, "changed metadata must recollect");
        fs::write(&database, "third!").unwrap();
        assert_eq!(
            cache.inventory(directory.path(), |_| Err("collector unavailable".into())),
            Err("collector unavailable".into())
        );
        assert!(
            cache.value.is_none(),
            "collection failure must drop old cached bytes"
        );
        assert_eq!(
            cache.inventory(directory.path(), collect).unwrap(),
            b"third!"
        );
        assert_eq!(collections.get(), 3);
        fs::remove_file(&database).unwrap();
        assert!(cache.inventory(directory.path(), collect).is_err());
        assert!(
            cache.value.is_none(),
            "key failure must drop old cached bytes"
        );
    }

    #[test]
    fn mutation_during_collection_cannot_publish_cached_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("rpmdb.sqlite");
        fs::write(&database, "before").unwrap();
        let mut cache = Cache::default();
        let result = cache.inventory(directory.path(), |directory| {
            fs::write(directory.join("new-wal"), "changed while collecting").unwrap();
            Ok(b"inventory".to_vec())
        });
        assert_eq!(
            result,
            Err("package environment changed while inspecting inventory".into())
        );
        assert!(cache.value.is_none());
    }
}
