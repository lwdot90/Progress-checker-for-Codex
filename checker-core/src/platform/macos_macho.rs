//! Bounded static Mach-O import inspection; never loads dyld or executes code.
//! This parser is deliberately incomplete: shared-cache-only libraries, fat
//! binaries, inherited runpath stacks and dynamic/plugin imports are refused or
//! outside its scope. Its output must never establish a qualified runtime closure.
//! Format reference: https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
use std::path::{Path, PathBuf};

const MAX_COMMAND_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMANDS: usize = 4096;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub install_name: String,
    pub weak: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticImports {
    pub cpu_type: u32,
    pub imports: Vec<Import>,
    pub rpaths: Vec<String>,
}

/// Parse only a thin little-endian 64-bit Mach-O header and load commands.
/// Caller may provide header+command bytes instead of reading the entire image.
pub fn parse(bytes: &[u8]) -> Result<StaticImports, String> {
    fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
        let word = bytes
            .get(offset..offset + 4)
            .ok_or("truncated Mach-O field")?;
        Ok(u32::from_le_bytes(
            word.try_into().map_err(|_| "invalid Mach-O field")?,
        ))
    }
    if bytes.len() < 32 || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        return Err("runtime inspection requires thin little-endian 64-bit Mach-O".into());
    }
    let cpu_type = u32_at(bytes, 4)?;
    if ![0x01000007, 0x0100000c].contains(&cpu_type) {
        return Err("unsupported Mach-O CPU type".into());
    }
    let file_type = u32_at(bytes, 12)?;
    if ![2, 6, 7, 8].contains(&file_type) {
        return Err(
            "runtime inspection requires executable, dylib, loader or bundle Mach-O".into(),
        );
    }
    if u32_at(bytes, 24)? & 0x80000000 != 0 {
        return Err(
            "shared-cache Mach-O identity requires a separately qualified cache collector".into(),
        );
    }
    let count = u32_at(bytes, 16)? as usize;
    let command_bytes = u32_at(bytes, 20)? as usize;
    if count > MAX_COMMANDS || command_bytes > MAX_COMMAND_BYTES {
        return Err("Mach-O command limits exceeded".into());
    }
    let end = 32usize
        .checked_add(command_bytes)
        .ok_or("Mach-O size overflow")?;
    if bytes.len() < end {
        return Err("truncated Mach-O load commands".into());
    }
    let mut offset = 32;
    let mut imports = Vec::new();
    let mut rpaths = Vec::new();
    for _ in 0..count {
        if offset + 8 > end {
            return Err("truncated Mach-O load command".into());
        }
        let command = u32_at(bytes, offset)?;
        let size = u32_at(bytes, offset + 4)? as usize;
        let next = offset.checked_add(size).ok_or("Mach-O command overflow")?;
        if size < 8 || size % 8 != 0 || next > end {
            return Err("invalid Mach-O command size or alignment".into());
        }
        if command == 0x27 {
            return Err("Mach-O dyld environment commands are unsupported".into());
        }
        let is_import = [0xc, 0xe, 0x80000018, 0x8000001f, 0x20, 0x80000023].contains(&command);
        let is_rpath = command == 0x8000001c;
        if is_import || is_rpath {
            let minimum = if is_import && command != 0xe { 24 } else { 12 };
            if size < minimum {
                return Err("truncated Mach-O path command".into());
            }
            let relative = u32_at(bytes, offset + 8)? as usize;
            if relative < minimum || relative >= size {
                return Err("invalid Mach-O string offset".into());
            }
            let value = &bytes[offset + relative..next];
            let length = value
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated Mach-O path")?;
            if length == 0 || length > MAX_PATH_BYTES {
                return Err("Mach-O path length exceeded".into());
            }
            let path =
                std::str::from_utf8(&value[..length]).map_err(|_| "non-UTF-8 Mach-O path")?;
            if path.chars().any(char::is_control) {
                return Err("control character in Mach-O path".into());
            }
            if is_rpath {
                rpaths.push(path.into());
            } else {
                imports.push(Import {
                    install_name: path.into(),
                    weak: command == 0x80000018,
                });
            }
        }
        offset = next;
    }
    if offset != end {
        return Err("Mach-O command count/size mismatch".into());
    }
    Ok(StaticImports {
        cpu_type,
        imports,
        rpaths,
    })
}

/// Expand explicit static paths only. Does not search PATH, environment, home,
/// fallback locations, shared cache, or inferred/inherited runpath stacks.
/// Every @rpath candidate is returned for caller-owned trust and ambiguity
/// checks; a candidate list is not a resolved runtime dependency identity.
pub fn candidates(
    install_name: &str,
    loader: &Path,
    executable: &Path,
    rpaths: &[String],
) -> Result<Vec<PathBuf>, String> {
    fn validate_text(value: &str) -> Result<(), String> {
        if value.is_empty() || value.len() > MAX_PATH_BYTES || value.chars().any(char::is_control) {
            return Err("Mach-O runtime path must be bounded and control-free".into());
        }
        Ok(())
    }
    fn relative_suffix(suffix: &str) -> Result<&Path, String> {
        validate_text(suffix)?;
        let path = Path::new(suffix);
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                        | std::path::Component::ParentDir
                        | std::path::Component::CurDir
                )
            })
        {
            return Err("Mach-O token suffix must be relative without traversal".into());
        }
        Ok(path)
    }
    fn expand(value: &str, loader: &Path, executable: &Path) -> Result<PathBuf, String> {
        validate_text(value)?;
        let path = if let Some(suffix) = value.strip_prefix("@loader_path/") {
            loader
                .parent()
                .ok_or("loader parent unavailable")?
                .join(relative_suffix(suffix)?)
        } else if let Some(suffix) = value.strip_prefix("@executable_path/") {
            executable
                .parent()
                .ok_or("executable parent unavailable")?
                .join(relative_suffix(suffix)?)
        } else if value.starts_with('/') {
            PathBuf::from(value)
        } else {
            return Err("relative or unsupported Mach-O runtime path".into());
        };
        if path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err("Mach-O runtime path traversal is unsupported".into());
        }
        Ok(path)
    }
    if !loader.is_absolute() || !executable.is_absolute() || rpaths.len() > MAX_COMMANDS {
        return Err("Mach-O resolution requires bounded absolute inputs".into());
    }
    for path in [loader, executable] {
        validate_text(
            path.to_str()
                .ok_or("Mach-O runtime input path must be UTF-8")?,
        )?;
        if path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err("Mach-O runtime input path traversal is unsupported".into());
        }
    }
    validate_text(install_name)?;
    for rpath in rpaths {
        validate_text(rpath)?;
    }
    if let Some(suffix) = install_name.strip_prefix("@rpath/") {
        if suffix.is_empty() || rpaths.is_empty() {
            return Err("Mach-O @rpath lacks explicit runpaths".into());
        }
        let suffix = relative_suffix(suffix)?;
        rpaths
            .iter()
            .map(|rpath| {
                let base = expand(rpath, loader, executable)?;
                let candidate = base.join(suffix);
                if candidate.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                }) {
                    return Err("Mach-O @rpath traversal is unsupported".into());
                }
                Ok(candidate)
            })
            .collect()
    } else {
        Ok(vec![expand(install_name, loader, executable)?])
    }
}

/// Explicit system-root policy for future native resolution. Broad /System,
/// Data volume, home and Homebrew roots are deliberately excluded.
pub fn is_system_runtime_path(path: &Path) -> bool {
    path.is_absolute()
        && ["/System/Library", "/usr/lib", "/usr/bin", "/bin", "/sbin"]
            .iter()
            .any(|root| path.starts_with(root))
        && !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

/// Inspect one native, immutable-by-unprivileged-users system image. Rechecks
/// requested alias, open-file identity and canonical pathname after bounded
/// command reads. Full executable content must still be bound by inventory.
pub fn inspect_system_file(path: &Path) -> Result<StaticImports, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("native macOS is required for trusted runtime inspection".into())
    }
    #[cfg(target_os = "macos")]
    {
        use std::{fs, io::Read, os::unix::fs::MetadataExt};
        fn identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u32) {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.mode(),
                metadata.uid(),
            )
        }
        let canonical = path.canonicalize().map_err(|e| e.to_string())?;
        if !is_system_runtime_path(&canonical) {
            return Err("Mach-O runtime is outside trusted system roots".into());
        }
        for ancestor in canonical.ancestors() {
            let metadata = fs::metadata(ancestor).map_err(|e| e.to_string())?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("Mach-O runtime path is replaceable by an untrusted user".into());
            }
        }
        let mut file = fs::File::open(&canonical).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() {
            return Err("Mach-O runtime must be a regular file".into());
        }
        let mut header = [0u8; 32];
        file.read_exact(&mut header)
            .map_err(|_| "truncated Mach-O header")?;
        let commands = u32::from_le_bytes(
            header[20..24]
                .try_into()
                .map_err(|_| "invalid command size")?,
        ) as usize;
        if commands > MAX_COMMAND_BYTES {
            return Err("Mach-O command limit exceeded".into());
        }
        let mut bytes = vec![0u8; 32 + commands];
        bytes[..32].copy_from_slice(&header);
        file.read_exact(&mut bytes[32..])
            .map_err(|_| "truncated Mach-O commands")?;
        let result = parse(&bytes)?;
        if identity(&file.metadata().map_err(|e| e.to_string())?) != identity(&before)
            || path.canonicalize().map_err(|e| e.to_string())? != canonical
            || identity(&fs::metadata(&canonical).map_err(|e| e.to_string())?) != identity(&before)
        {
            return Err("Mach-O runtime changed during inspection".into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str, command: u32) -> Vec<u8> {
        let minimum = if command == 0x8000001c { 12 } else { 24 };
        let size = (minimum + name.len() + 1 + 7) / 8 * 8;
        let mut bytes = vec![0u8; 32 + size];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[32..36].copy_from_slice(&command.to_le_bytes());
        bytes[36..40].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[40..44].copy_from_slice(&(minimum as u32).to_le_bytes());
        bytes[32 + minimum..32 + minimum + name.len()].copy_from_slice(name.as_bytes());
        bytes
    }
    #[test]
    fn parses_import_and_rejects_truncated_or_unbounded_commands() {
        let bytes = fixture("/usr/lib/libSystem.B.dylib", 0xc);
        assert_eq!(
            parse(&bytes).unwrap().imports[0].install_name,
            "/usr/lib/libSystem.B.dylib"
        );
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        let mut excessive = bytes;
        excessive[16..20].copy_from_slice(&4097u32.to_le_bytes());
        assert!(parse(&excessive).is_err());
    }
    #[test]
    fn explicit_paths_refuse_traversal_home_and_inferred_rpaths() {
        assert!(
            candidates(
                "@rpath/lib.dylib",
                Path::new("/usr/bin/helper"),
                Path::new("/usr/bin/app"),
                &[]
            )
            .is_err()
        );
        assert!(
            candidates(
                "@loader_path/../secret",
                Path::new("/usr/bin/helper"),
                Path::new("/usr/bin/app"),
                &[]
            )
            .is_err()
        );
        assert!(!is_system_runtime_path(Path::new(
            "/System/Volumes/Data/Users/person/secret"
        )));
        assert!(is_system_runtime_path(Path::new(
            "/System/Library/dyld/cache"
        )));
    }
    #[test]
    fn token_suffix_cannot_replace_base_or_bypass_direct_input_bounds() {
        let loader = Path::new("/usr/bin/helper");
        let executable = Path::new("/usr/bin/app");
        for value in [
            "@loader_path//usr/lib/X",
            "@executable_path//usr/lib/X",
            "@rpath//usr/lib/X",
        ] {
            assert!(candidates(value, loader, executable, &["/usr/lib".into()]).is_err());
        }
        assert!(
            candidates(
                &format!("/usr/lib/{}", "x".repeat(MAX_PATH_BYTES)),
                loader,
                executable,
                &[]
            )
            .is_err()
        );
        assert!(candidates("/usr/lib/X\0Y", loader, executable, &[]).is_err());
        assert!(
            candidates(
                "/usr/lib/X",
                Path::new("/usr/bin/../helper"),
                executable,
                &[]
            )
            .is_err()
        );
        assert!(candidates("@rpath/X", loader, executable, &["/usr/lib\n".into()]).is_err());
    }
}
