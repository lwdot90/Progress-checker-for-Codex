//! Bounded static PE import inspection. Never loads a DLL or executes an image.
//! Results are a dependency discovery aid, not a complete runtime closure:
//! dynamically loaded libraries and interpreter modules need an explicit policy.
//! https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
//! https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

use std::{collections::BTreeSet, path::PathBuf};
const MAX_IMAGE: usize = 128 * 1024 * 1024;
const MAX_IMPORTS: usize = 512;

fn word(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or("PE offset overflow")?)
        .ok_or("truncated PE field")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}
fn dword(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or("PE offset overflow")?)
        .ok_or("truncated PE field")?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| "truncated PE field")?,
    ))
}
#[derive(Clone, Copy)]
struct Section {
    virtual_start: u32,
    virtual_size: u32,
    raw_start: u32,
    raw_size: u32,
}
fn file_offset(
    rva: u32,
    length: usize,
    sections: &[Section],
    bytes: &[u8],
) -> Result<usize, String> {
    let mut found = None;
    for section in sections {
        if let Some(relative) = rva.checked_sub(section.virtual_start) {
            if relative < section.virtual_size.max(section.raw_size) {
                let end = usize::try_from(relative)
                    .map_err(|_| "PE offset overflow")?
                    .checked_add(length)
                    .ok_or("PE offset overflow")?;
                if end > section.raw_size as usize {
                    return Err("PE RVA references unbacked section bytes".into());
                }
                let offset = usize::try_from(section.raw_start)
                    .map_err(|_| "PE offset overflow")?
                    .checked_add(relative as usize)
                    .ok_or("PE offset overflow")?;
                if offset.checked_add(length).ok_or("PE offset overflow")? > bytes.len() {
                    return Err("PE RVA exceeds image bytes".into());
                }
                if found.replace(offset).is_some() {
                    return Err("ambiguous overlapping PE sections".into());
                }
            }
        }
    }
    found.ok_or_else(|| "PE RVA does not map to a file-backed section".into())
}
fn valid_dll_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.to_ascii_lowercase().ends_with(".dll")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !name.contains("..")
}

/// PE32 and PE32+ normal imports. Nonempty delay-import directories are refused
/// until delay-load semantics can be bound to an exact runtime search policy.
pub fn imported_dlls(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() > MAX_IMAGE || bytes.get(..2) != Some(b"MZ") {
        return Err("unsupported PE image".into());
    }
    let pe = dword(bytes, 0x3c)? as usize;
    if bytes.get(pe..pe.checked_add(4).ok_or("PE offset overflow")?) != Some(b"PE\0\0") {
        return Err("invalid PE signature".into());
    }
    let count = usize::from(word(bytes, pe + 6)?);
    if count == 0 || count > 96 {
        return Err("PE section count unsupported".into());
    }
    let optional_size = usize::from(word(bytes, pe + 20)?);
    let optional = pe.checked_add(24).ok_or("PE offset overflow")?;
    let end = optional
        .checked_add(optional_size)
        .ok_or("PE offset overflow")?;
    if end > bytes.len() {
        return Err("truncated PE optional header".into());
    }
    let (directory_count, directories) = match word(bytes, optional)? {
        0x10b => (optional + 92, optional + 96),
        0x20b => (optional + 108, optional + 112),
        _ => return Err("unsupported PE optional-header kind".into()),
    };
    if directory_count + 4 > end {
        return Err("truncated PE directory count".into());
    }
    let directories_count = dword(bytes, directory_count)? as usize;
    if directories_count > 16
        || directories
            .checked_add(directories_count * 8)
            .ok_or("PE offset overflow")?
            > end
    {
        return Err("unsupported PE directory layout".into());
    }
    if directories_count > 13
        && (dword(bytes, directories + 13 * 8)? != 0
            || dword(bytes, directories + 13 * 8 + 4)? != 0)
    {
        return Err("delay-import dependency closure is not qualified".into());
    }
    let mut sections = Vec::new();
    for index in 0..count {
        let offset = end.checked_add(index * 40).ok_or("PE offset overflow")?;
        if offset + 40 > bytes.len() {
            return Err("truncated PE section header".into());
        }
        sections.push(Section {
            virtual_size: dword(bytes, offset + 8)?,
            virtual_start: dword(bytes, offset + 12)?,
            raw_size: dword(bytes, offset + 16)?,
            raw_start: dword(bytes, offset + 20)?,
        });
    }
    if directories_count < 2 {
        return Ok(Vec::new());
    }
    let rva = dword(bytes, directories + 8)?;
    let size = dword(bytes, directories + 12)? as usize;
    if rva == 0 && size == 0 {
        return Ok(Vec::new());
    }
    if rva == 0 || !(20..=1024 * 1024).contains(&size) {
        return Err("invalid PE import directory bounds".into());
    }
    let start = file_offset(rva, size, &sections, bytes)?;
    let mut imports = BTreeSet::new();
    for index in 0..=MAX_IMPORTS {
        let offset = start.checked_add(index * 20).ok_or("PE offset overflow")?;
        if offset + 20 > start + size {
            return Err("unterminated PE import directory".into());
        }
        if bytes[offset..offset + 20].iter().all(|byte| *byte == 0) {
            return Ok(imports.into_iter().collect());
        }
        if index == MAX_IMPORTS {
            return Err("PE import count exceeds limit".into());
        }
        let name_rva = dword(bytes, offset + 12)?;
        let mut name = Vec::new();
        for position in 0..=255_u32 {
            let offset = file_offset(
                name_rva.checked_add(position).ok_or("PE name overflow")?,
                1,
                &sections,
                bytes,
            )?;
            if bytes[offset] == 0 {
                break;
            }
            name.push(bytes[offset]);
        }
        let name = std::str::from_utf8(&name).map_err(|_| "unsupported PE DLL name encoding")?;
        if !valid_dll_name(name) {
            return Err("unsupported PE DLL import name".into());
        }
        imports.insert(name.to_ascii_lowercase());
    }
    Err("PE import count exceeds limit".into())
}

/// Resolve only exact names inside explicit trusted directories, never PATH,
/// cwd, registry or loader search order. Caller must audit roots and collect the
/// resulting files with retained InstallationTrustGuard/RuntimeManifest guards.
/// API-set virtual imports are refused: a validated OS API-set resolver is absent.
pub fn resolve_dependencies(names: &[String], roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if roots.is_empty() || roots.len() > 16 || names.len() > MAX_IMPORTS {
        return Err("dependency resolution limits exceeded".into());
    }
    let mut canonical_roots = Vec::new();
    for root in roots {
        if !root.is_absolute() {
            return Err("trusted DLL directory must be absolute".into());
        }
        let root = root
            .canonicalize()
            .map_err(|_| "trusted DLL directory unavailable")?;
        if !root.is_dir() {
            return Err("trusted DLL root is not a directory".into());
        }
        canonical_roots.push(root);
    }
    let mut result = BTreeSet::new();
    for name in names {
        if !valid_dll_name(name) {
            return Err("invalid dependency name".into());
        }
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("api-ms-") || lower.starts_with("ext-ms-") {
            return Err("Windows API-set dependency resolution is not qualified".into());
        }
        let mut resolved = None;
        for root in &canonical_roots {
            let candidate = root.join(name);
            if !candidate
                .try_exists()
                .map_err(|_| "dependency path inaccessible")?
            {
                continue;
            }
            let path = candidate
                .canonicalize()
                .map_err(|_| "dependency path unavailable")?;
            if path.parent() != Some(root.as_path()) || !path.is_file() {
                return Err("dependency escapes exact trusted directory".into());
            }
            if resolved.replace(path).is_some() {
                return Err("ambiguous dependency in trusted directories".into());
            }
        }
        result.insert(resolved.ok_or("dependency absent from explicit trusted directories")?);
    }
    Ok(result.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(plus: bool) -> Vec<u8> {
        let mut image = vec![0_u8; 1024];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        image[64..68].copy_from_slice(b"PE\0\0");
        image[70..72].copy_from_slice(&1_u16.to_le_bytes());
        let optional_size: u16 = if plus { 240 } else { 224 };
        image[84..86].copy_from_slice(&optional_size.to_le_bytes());
        let magic: u16 = if plus { 0x20b } else { 0x10b };
        image[88..90].copy_from_slice(&magic.to_le_bytes());
        let directory = 88 + if plus { 112 } else { 96 };
        image[directory - 4..directory].copy_from_slice(&16_u32.to_le_bytes());
        image[directory + 8..directory + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[directory + 12..directory + 16].copy_from_slice(&40_u32.to_le_bytes());
        let section = 88 + usize::from(optional_size);
        for (field, value) in [(8, 512_u32), (12, 0x1000), (16, 512), (20, 512)] {
            image[section + field..section + field + 4].copy_from_slice(&value.to_le_bytes());
        }
        image[524..528].copy_from_slice(&0x1030_u32.to_le_bytes());
        image[560..573].copy_from_slice(b"KERNEL32.dll\0");
        image
    }
    #[test]
    fn normal_imports_parse_both_native_optional_header_kinds() {
        for plus in [false, true] {
            assert_eq!(imported_dlls(&fixture(plus)).unwrap(), vec!["kernel32.dll"]);
        }
    }
    #[test]
    fn truncated_images_and_delayed_or_unmapped_imports_are_refused() {
        let image = fixture(false);
        for length in [0, 1, 64, 87, 300, 350, 527] {
            assert!(imported_dlls(&image[..length]).is_err());
        }
        let mut delayed = image.clone();
        delayed[88 + 96 + 13 * 8..88 + 96 + 13 * 8 + 4].copy_from_slice(&1_u32.to_le_bytes());
        assert!(
            imported_dlls(&delayed)
                .unwrap_err()
                .contains("delay-import")
        );
        let mut unmapped = image;
        unmapped[524..528].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        assert!(imported_dlls(&unmapped).is_err());
    }
    #[test]
    fn resolver_rejects_api_sets_and_escaping_import_names() {
        let root = tempfile::tempdir().unwrap();
        for name in ["../x.dll", "x\\y.dll", "api-ms-win-core-file-l1-1-0.dll"] {
            assert!(resolve_dependencies(&[name.into()], &[root.path().into()]).is_err());
        }
    }
}
