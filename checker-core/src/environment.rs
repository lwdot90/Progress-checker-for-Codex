//! Process-local system-package inventory caching. Source fingerprints are never cached.

#[cfg(target_os = "linux")]
pub use linux::package_inventory;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::with_test_inventory;

/// Native runtime collectors are building blocks, not a complete dependency
/// closure. Never substitute an empty or partial manifest for package freshness.
#[cfg(not(target_os = "linux"))]
pub fn package_inventory() -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    let reason = "macOS environment unavailable: approved runtime dependency closure is not integrated or qualified";
    #[cfg(target_os = "windows")]
    let reason = "native Windows environment unavailable: approved runtime dependency closure is not integrated or qualified";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let reason = "system environment inventory unsupported on this platform";
    Err(reason.into())
}

#[cfg(target_os = "linux")]
mod linux {
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
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Provider {
        Rpm,
        Dpkg,
    }
    impl Provider {
        fn executable(self) -> &'static Path {
            Path::new(match self {
                Self::Rpm => "/usr/bin/rpm",
                Self::Dpkg => "/usr/bin/dpkg-query",
            })
        }
    }
    fn policy_from_release(text: &str) -> Result<Provider, String> {
        let mut id = None;
        let mut like = None;
        for line in text.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, raw)) = line.split_once('=') else {
                return Err("malformed OS release record".into());
            };
            if key != "ID" && key != "ID_LIKE" {
                continue;
            }
            let value = if raw.starts_with('"') || raw.starts_with('\'') {
                let quote = raw.as_bytes()[0];
                if raw.len() < 2 || raw.as_bytes()[raw.len() - 1] != quote {
                    return Err("malformed OS release identity quoting".into());
                }
                &raw[1..raw.len() - 1]
            } else {
                raw
            };
            if value.is_empty()
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                        || key == "ID_LIKE" && byte == b' '
                })
            {
                return Err("malformed OS release identity".into());
            }
            let slot = if key == "ID" { &mut id } else { &mut like };
            if slot.replace(value).is_some() {
                return Err("duplicate OS release identity".into());
            }
        }
        let id = id.ok_or("OS release ID missing")?;
        let family = |value: &str| match value {
            "ubuntu" | "debian" => Some(Provider::Dpkg),
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => Some(Provider::Rpm),
            _ => None,
        };
        let mut selected = family(id);
        for value in like.unwrap_or("").split_whitespace() {
            if let Some(candidate) = family(value) {
                if selected.is_some_and(|selected| selected != candidate) {
                    return Err("ambiguous OS package-manager family".into());
                }
                selected = Some(candidate);
            }
        }
        selected.ok_or_else(|| "unsupported OS package-manager family".into())
    }

    fn trusted_release_metadata(metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= 65536
    }

    fn os_policy() -> Result<(Provider, Stamp, String), String> {
        use sha2::{Digest, Sha256};
        let path = Path::new("/etc/os-release");
        let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
        if !trusted_release_metadata(&metadata) {
            return Err("OS release must be a bounded root-owned non-writable regular file".into());
        }
        let before = stamp(path)?;
        let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        if opened.dev() != before.dev
            || opened.ino() != before.ino
            || opened.uid() != 0
            || opened.mode() & 0o022 != 0
        {
            return Err("OS release file identity changed while opening".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 65536
            || stamp(path)? != before
            || file.metadata().map_err(|error| error.to_string())?.len() != before.len
        {
            return Err("OS release changed during inspection".into());
        }
        let selected = policy_from_release(
            std::str::from_utf8(&bytes).map_err(|_| "invalid OS release encoding")?,
        )?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let mut bound = before;
        bound.name = format!("{}#sha256:{}", bound.name, digest);
        Ok((selected, bound, digest))
    }
    fn dpkg_database_key(directory: &Path, executable: &Path) -> Result<Vec<Stamp>, String> {
        let updates = directory.join("updates");
        // Any pending fragment makes the snapshot uncertain. Inspect at most one
        // entry so unexpected directory size cannot allocate an unbounded list.
        let mut entries = fs::read_dir(&updates).map_err(|e| e.to_string())?;
        if let Some(entry) = entries.next() {
            entry.map_err(|e| e.to_string())?;
            return Err(
                "dpkg database has pending updates; retry after package operations finish".into(),
            );
        }
        Ok(vec![
            stamp(directory)?,
            stamp(executable)?,
            stamp(&directory.join("status"))?,
            stamp(&updates)?,
        ])
    }
    fn database_key(
        directory: &Path,
        selected: Provider,
        executable: &Path,
    ) -> Result<Vec<Stamp>, String> {
        let directory = directory.canonicalize().map_err(|e| e.to_string())?;
        if selected == Provider::Dpkg {
            return dpkg_database_key(&directory, executable);
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            // SQLite shared-memory bookkeeping and the lock file do not contain
            // package data. Queries modify SHM; main DB and WAL remain watched.
            if matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some("rpmdb.sqlite-shm" | ".rpm.lock")
            ) {
                continue;
            }
            paths.push(path);
            if paths.len() == 129 {
                return Err("unsupported RPM database layout".into());
            }
        }
        paths.sort();
        if paths.is_empty() || paths.len() > 128 {
            return Err("unsupported RPM database layout".into());
        }
        let mut key = vec![stamp(&directory)?, stamp(executable)?];
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
        #[cfg(test)]
        fn inventory(
            &mut self,
            directory: &Path,
            collect: impl FnOnce(&Path) -> Result<Vec<u8>, String>,
        ) -> Result<Vec<u8>, String> {
            self.inventory_for(directory, Provider::Rpm, collect)
        }
        fn inventory_for(
            &mut self,
            directory: &Path,
            selected: Provider,
            collect: impl FnOnce(&Path) -> Result<Vec<u8>, String>,
        ) -> Result<Vec<u8>, String> {
            self.inventory_with_key(
                directory,
                || database_key(directory, selected, selected.executable()),
                collect,
            )
        }
        fn inventory_with_key(
            &mut self,
            directory: &Path,
            key: impl Fn() -> Result<Vec<Stamp>, String>,
            collect: impl FnOnce(&Path) -> Result<Vec<u8>, String>,
        ) -> Result<Vec<u8>, String> {
            let before = match key() {
                Ok(key) => key,
                Err(error) => {
                    self.value = None;
                    return Err(error);
                }
            };
            if let Some((cached_key, bytes)) = &self.value
                && *cached_key == before
                && key().is_ok_and(|key| key == before)
            {
                return Ok(bytes.clone());
            }
            self.value = None;
            let bytes = collect(directory)?;
            if key()? != before {
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
                provider.cache.inventory(&provider.directory, |directory| {
                    collect_inventory(directory, Provider::Rpm)
                })
            })
        }) {
            return result;
        }
        let mut cache = CACHE
            .get_or_init(|| Mutex::new(Cache::default()))
            .lock()
            .map_err(|_| "environment cache unavailable")?;
        let (selected, _, release_digest) = match os_policy() {
            Ok(policy) => policy,
            Err(error) => {
                cache.value = None;
                return Err(error);
            }
        };
        let directory = match selected {
            Provider::Dpkg => Path::new("/var/lib/dpkg"),
            Provider::Rpm => Path::new("/usr/lib/sysimage/rpm"),
        };
        if selected == Provider::Dpkg {
            for path in [
                directory.to_owned(),
                selected.executable().to_owned(),
                directory.join("status"),
                directory.join("updates"),
            ] {
                let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    cache.value = None;
                    return Err(
                        "dpkg inventory paths must be root-owned and not group/world writable"
                            .into(),
                    );
                }
            }
            if !fs::metadata(directory.join("status"))
                .map_err(|error| error.to_string())?
                .is_file()
                || !fs::metadata(selected.executable())
                    .map_err(|error| error.to_string())?
                    .is_file()
            {
                cache.value = None;
                return Err("dpkg inventory executable and status must be regular files".into());
            }
        }
        cache.inventory_with_key(
            directory,
            || {
                let (current, release, current_digest) = os_policy()?;
                if current_digest != release_digest {
                    return Err("OS release content changed during inventory".into());
                }
                if current != selected {
                    return Err("OS package-manager policy changed during inventory".into());
                }
                let mut key = database_key(directory, selected, selected.executable())?;
                key.push(release);
                Ok(key)
            },
            |directory| {
                let mut bytes = format!("os-release-sha256:{release_digest}\n").into_bytes();
                bytes.extend(collect_inventory(directory, selected)?);
                Ok(bytes)
            },
        )
    }

    fn collect_inventory(directory: &Path, selected: Provider) -> Result<Vec<u8>, String> {
        let output = tempfile::tempfile().map_err(|e| e.to_string())?;
        let mut command = std::process::Command::new(selected.executable());
        command.env_clear();
        match selected {
            Provider::Rpm => {
                command.arg("--dbpath").arg(directory).args([
                    "-qa",
                    "--qf",
                    "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n",
                ]);
            }
            Provider::Dpkg => {
                command
                    .arg(format!("--admindir={}", directory.display()))
                    .args([
                        "--show",
                        "--showformat=${binary:Package}\t${Architecture}\t${Version}\t${Status}\n",
                    ]);
            }
        }
        let mut child = command
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
        if selected == Provider::Dpkg {
            validate_dpkg_inventory(&bytes)?;
        }
        let mut tagged = match selected {
            Provider::Rpm => b"provider:rpm-v1\n".to_vec(),
            Provider::Dpkg => b"provider:dpkg-v1\n".to_vec(),
        };
        tagged.extend(bytes);
        Ok(tagged)
    }

    fn validate_dpkg_inventory(bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "invalid dpkg inventory encoding")?;
        if text.is_empty() || !text.ends_with('\n') {
            return Err("incomplete dpkg inventory".into());
        }
        for line in text.lines() {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4
                || fields[0].is_empty()
                || fields[..3]
                    .iter()
                    .any(|field| field.chars().any(char::is_control))
            {
                return Err("malformed dpkg inventory".into());
            }
            let status: Vec<_> = fields[3].split(' ').collect();
            if status.len() != 3
                || !["unknown", "install", "hold", "deinstall", "purge"].contains(&status[0])
                || !["ok", "reinstreq"].contains(&status[1])
                || ![
                    "not-installed",
                    "config-files",
                    "half-installed",
                    "unpacked",
                    "half-configured",
                    "triggers-awaited",
                    "triggers-pending",
                    "installed",
                ]
                .contains(&status[2])
            {
                return Err("malformed dpkg package status".into());
            }
            // dpkg permits incomplete metadata during first unpack and legacy
            // config-files without Architecture. Preserve raw empty fields in
            // the hash rather than omitting rows or inventing identity values.
            if fields[2].is_empty() && status[2] != "half-installed"
                || fields[1].is_empty() && !["half-installed", "config-files"].contains(&status[2])
            {
                return Err("incomplete dpkg package metadata for package state".into());
            }
        }
        Ok(())
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
        #[test]
        fn release_rewrite_atomic_replacement_and_symlink_retarget_change_identity() {
            use sha2::{Digest, Sha256};
            use std::os::unix::fs::symlink;
            let root = tempfile::tempdir().unwrap();
            let release = root.path().join("os-release");
            let identity = |path: &Path| {
                (
                    stamp(path).unwrap(),
                    format!("{:x}", Sha256::digest(fs::read(path).unwrap())),
                )
            };
            fs::write(&release, b"ID=fedora\n").unwrap();
            let before = identity(&release);
            std::thread::sleep(Duration::from_millis(2));
            fs::write(&release, b"ID=ubuntu\n").unwrap();
            assert_ne!(before, identity(&release));
            let replacement = root.path().join("replacement");
            fs::write(&replacement, b"ID=ubuntu\n").unwrap();
            let rewritten = identity(&release);
            fs::rename(&replacement, &release).unwrap();
            assert_ne!(rewritten, identity(&release));
            let other = root.path().join("other-release");
            fs::write(&other, b"ID=ubuntu\n").unwrap();
            let alias = root.path().join("release-link");
            symlink(&release, &alias).unwrap();
            assert_eq!(identity(&release).1, identity(&alias).1);
            let linked = identity(&alias);
            fs::remove_file(&alias).unwrap();
            symlink(&other, &alias).unwrap();
            assert_ne!(linked, identity(&alias));
        }

        #[test]
        fn release_permission_policy_rejects_group_and_world_writable_metadata() {
            use std::os::unix::fs::PermissionsExt;
            let root = tempfile::tempdir().unwrap();
            let release = root.path().join("os-release");
            fs::write(&release, b"ID=fedora\n").unwrap();
            for mode in [0o664, 0o646, 0o666] {
                fs::set_permissions(&release, fs::Permissions::from_mode(mode)).unwrap();
                let metadata = fs::metadata(&release).unwrap();
                assert!(!trusted_release_metadata(&metadata));
            }
            fs::set_permissions(&release, fs::Permissions::from_mode(0o644)).unwrap();
            let metadata = fs::metadata(&release).unwrap();
            assert_eq!(trusted_release_metadata(&metadata), metadata.uid() == 0);
            fs::write(&release, vec![b'x'; 65537]).unwrap();
            assert!(!trusted_release_metadata(&fs::metadata(&release).unwrap()));
            assert!(!trusted_release_metadata(
                &fs::metadata(root.path()).unwrap()
            ));
        }

        #[test]
        fn rpm_entry_limit_preserves_bookkeeping_exclusions_and_refuses_extra_data() {
            let root = tempfile::tempdir().unwrap();
            let database = root.path().join("rpm");
            fs::create_dir(&database).unwrap();
            let executable = root.path().join("query-fixture");
            fs::write(&executable, "executable").unwrap();
            for index in 0..128 {
                fs::write(database.join(format!("data-{index}")), "data").unwrap();
            }
            fs::write(database.join("rpmdb.sqlite-shm"), "ignored").unwrap();
            fs::write(database.join(".rpm.lock"), "ignored").unwrap();
            assert_eq!(
                database_key(&database, Provider::Rpm, &executable)
                    .unwrap()
                    .len(),
                130
            );
            fs::write(database.join("extra-data"), "data").unwrap();
            assert!(
                database_key(&database, Provider::Rpm, &executable)
                    .unwrap_err()
                    .contains("unsupported RPM")
            );
        }

        #[test]
        fn authoritative_release_selects_family_without_database_fallback() {
            assert_eq!(
                policy_from_release("ID=fedora\nID_LIKE=\"rhel fedora\"\n"),
                Ok(Provider::Rpm)
            );
            assert_eq!(
                policy_from_release("ID=ubuntu\nID_LIKE=debian\n"),
                Ok(Provider::Dpkg)
            );
            assert_eq!(
                policy_from_release("ID=derivative\nID_LIKE='debian'\n"),
                Ok(Provider::Dpkg)
            );
            for release in [
                "ID=unknown\n",
                "ID_LIKE=debian\n",
                "ID=ubuntu\nID_LIKE=rhel\n",
                "ID=\"ubuntu\n",
                "ID=ubuntu\nID=fedora\n",
                "ID=$(ubuntu)\n",
            ] {
                assert!(policy_from_release(release).is_err(), "{release:?}");
            }
            // Even with both databases present, ID remains authoritative;
            // this pure selector has no filesystem/database-existence input.
        }

        #[test]
        fn dpkg_parser_preserves_all_known_states_and_rejects_malformed_output() {
            for state in [
                "not-installed",
                "config-files",
                "half-installed",
                "unpacked",
                "half-configured",
                "triggers-awaited",
                "triggers-pending",
                "installed",
            ] {
                let row = format!("libexample:amd64\tamd64\t1.0-1\thold reinstreq {state}\n");
                assert!(validate_dpkg_inventory(row.as_bytes()).is_ok());
            }
            for row in [
                "",
                "lib\tamd64\t1\tinstall ok installed",
                "lib\t\t1\tinstall ok installed\n",
                "lib\tamd64\t1\tinstall ok surprise\n",
                "lib\tamd64\t1\tinstall ok installed\textra\n",
            ] {
                assert!(validate_dpkg_inventory(row.as_bytes()).is_err(), "{row:?}");
            }
            assert!(validate_dpkg_inventory(b"legacy\t\t1.0\tdeinstall ok config-files\n").is_ok());
            assert!(
                validate_dpkg_inventory(b"unpacking\t\t\tinstall reinstreq half-installed\n")
                    .is_ok()
            );
            assert!(
                validate_dpkg_inventory(b"legacy\tamd64\t\tdeinstall ok config-files\n").is_err()
            );
            assert!(validate_dpkg_inventory(b"installed\t\t1.0\tinstall ok installed\n").is_err());
            assert!(validate_dpkg_inventory(&[0xff, b'\n']).is_err());
        }

        #[test]
        fn dpkg_cache_tracks_status_rewrites_and_refuses_pending_updates() {
            use std::cell::Cell;
            // Fixture paths are supplied only to the internal metadata-key helper;
            // production executable selection remains fixed and caller-independent.
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("fixture-query");
            fs::write(&executable, "trusted fixture executable").unwrap();
            fs::create_dir(directory.path().join("updates")).unwrap();
            fs::write(directory.path().join("status"), "before").unwrap();
            let key = || database_key(directory.path(), Provider::Dpkg, &executable);
            let calls = Cell::new(0);
            let collect = |directory: &Path| {
                calls.set(calls.get() + 1);
                fs::read(directory.join("status")).map_err(|error| error.to_string())
            };
            let mut cache = Cache::default();
            assert_eq!(
                cache
                    .inventory_with_key(directory.path(), key, collect)
                    .unwrap(),
                b"before"
            );
            assert_eq!(
                cache
                    .inventory_with_key(directory.path(), key, collect)
                    .unwrap(),
                b"before"
            );
            assert_eq!(calls.get(), 1);
            std::thread::sleep(Duration::from_millis(2));
            fs::write(directory.path().join("status"), "after!").unwrap();
            assert_eq!(
                cache
                    .inventory_with_key(directory.path(), key, collect)
                    .unwrap(),
                b"after!"
            );
            assert_eq!(calls.get(), 2);
            fs::write(directory.path().join("updates/0000"), "pending").unwrap();
            assert!(
                cache
                    .inventory_with_key(directory.path(), key, collect)
                    .unwrap_err()
                    .contains("pending updates")
            );
            assert!(cache.value.is_none());
            fs::remove_file(directory.path().join("updates/0000")).unwrap();
            assert_eq!(
                cache
                    .inventory_with_key(directory.path(), key, collect)
                    .unwrap(),
                b"after!"
            );
            assert_eq!(calls.get(), 3);
            let result = cache.inventory_with_key(directory.path(), key, |_| {
                panic!("warm cache should avoid collection")
            });
            assert!(result.is_ok());
            fs::write(directory.path().join("status"), "third!").unwrap();
            let result = cache.inventory_with_key(directory.path(), key, |directory| {
                fs::write(directory.join("updates/0001"), "transition").unwrap();
                Ok(b"partial".to_vec())
            });
            assert!(result.is_err());
            assert!(cache.value.is_none());
        }
    }
}
