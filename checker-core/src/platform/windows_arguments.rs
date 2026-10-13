//! Pure UTF-16 launch buffers for a direct native executable, never a shell.
//! Microsoft CRT argument convention only: programs with custom parsers require
//! their own reviewed adapter. No process creation or executable trust here.
//! https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments

#[derive(Debug, PartialEq, Eq)]
pub struct WindowsArguments {
    /// Pass explicitly as lpApplicationName; do not permit executable discovery.
    pub application: Vec<u16>,
    /// Mutable, NUL-terminated storage for CreateProcessW's lpCommandLine.
    pub command_line: Vec<u16>,
}

pub fn encode(application: &str, arguments: &[String]) -> Result<WindowsArguments, String> {
    let drive_absolute = application
        .as_bytes()
        .get(0)
        .is_some_and(u8::is_ascii_alphabetic)
        && application.as_bytes().get(1) == Some(&b':')
        && application
            .as_bytes()
            .get(2)
            .is_some_and(|byte| matches!(*byte, b'\\' | b'/'));
    let unc = application.starts_with("\\\\")
        && !application.starts_with("\\\\?\\")
        && !application.starts_with("\\\\.\\")
        && application[2..]
            .split('\\')
            .filter(|part| !part.is_empty())
            .count()
            >= 3;
    if !(drive_absolute || unc)
        || application.contains(['\0', '"'])
        || application.ends_with(['\\', '/'])
        || !application.to_ascii_lowercase().ends_with(".exe")
        || application
            .split(['\\', '/'])
            .any(|part| part == "." || part == "..")
    {
        return Err("Windows application requires an explicit absolute .exe path without NUL, quotes or relative components".into());
    }
    // argv[0] follows special CRT rules: quotes protect spaces but backslashes
    // remain literal. Ordinary arguments use the backslash/quote grammar below.
    let mut line = format!("\"{application}\"");
    for argument in arguments {
        if argument.contains('\0') {
            return Err("Windows argument contains NUL".into());
        }
        line.push(' ');
        line.push('"');
        let mut backslashes = 0;
        for ch in argument.chars() {
            if ch == '\\' {
                backslashes += 1;
                continue;
            }
            let count = if ch == '"' {
                backslashes * 2 + 1
            } else {
                backslashes
            };
            line.extend(std::iter::repeat_n('\\', count));
            line.push(ch);
            backslashes = 0;
        }
        line.extend(std::iter::repeat_n('\\', backslashes * 2));
        line.push('"');
        if line.encode_utf16().count() >= 32_767 {
            return Err("Windows command line exceeds CreateProcessW UTF-16 limit".into());
        }
    }
    let command_line: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
    if command_line.len() > 32_767 {
        return Err("Windows command line exceeds CreateProcessW UTF-16 limit".into());
    }
    Ok(WindowsArguments {
        application: application.encode_utf16().chain(Some(0)).collect(),
        command_line,
    })
}

/// Serialize only explicitly supplied policy values, never the host environment.
/// This validates representation, not path trust or sandbox ACLs. The broker must
/// bind exact fixed values to the approved policy before calling this function.
pub fn encode_environment(entries: &[(String, String)]) -> Result<Vec<u16>, String> {
    let mut entries: Vec<(&str, &str)> = entries
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    for (key, value) in &entries {
        if key.contains(['\0', '='])
            || value.contains('\0')
            || !["SYSTEMROOT", "PATH", "TEMP", "TMP"].contains(&key.to_ascii_uppercase().as_str())
        {
            return Err("Windows environment requires only explicit SystemRoot/PATH/TEMP/TMP keys and NUL-free values".into());
        }
    }
    entries.sort_by_key(|(key, _)| key.to_ascii_uppercase());
    if entries
        .windows(2)
        .any(|pair| pair[0].0.eq_ignore_ascii_case(pair[1].0))
    {
        return Err("Windows environment has case-equivalent duplicate keys".into());
    }
    let mut result = Vec::new();
    for (key, value) in entries {
        result.extend(key.to_ascii_uppercase().encode_utf16());
        result.push('=' as u16);
        result.extend(value.encode_utf16());
        result.push(0);
        if result.len() >= 32_767 {
            return Err("Windows environment exceeds bounded UTF-16 policy limit".into());
        }
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}

/// Canonicality and existence are separately checked by the broker using native
/// file identities. This pure encoder rejects relative/device/NUL input only.
pub fn encode_cwd(cwd: &str) -> Result<Vec<u16>, String> {
    let drive_absolute = cwd.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && cwd.as_bytes().get(1) == Some(&b':')
        && cwd
            .as_bytes()
            .get(2)
            .is_some_and(|byte| matches!(*byte, b'\\' | b'/'));
    let unc = cwd.starts_with("\\\\")
        && !cwd.starts_with("\\\\?\\")
        && !cwd.starts_with("\\\\.\\")
        && cwd[2..].split('\\').filter(|part| !part.is_empty()).count() >= 2;
    if !(drive_absolute || unc)
        || cwd.contains(['\0', '"'])
        || cwd
            .split(['\\', '/'])
            .any(|part| part == "." || part == "..")
    {
        return Err("Windows cwd requires explicit absolute path without device syntax, NUL or relative components".into());
    }
    let result: Vec<u16> = cwd.encode_utf16().chain(Some(0)).collect();
    if result.len() > 32_767 {
        return Err("Windows cwd exceeds bounded UTF-16 policy limit".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_is_explicit_sorted_bounded_and_double_nul_terminated() {
        let entries = vec![
            ("tmp".into(), "".into()),
            ("path".into(), "C:\\工具😀".into()),
            ("SystemRoot".into(), "C:\\Windows".into()),
        ];
        let result = encode_environment(&entries).unwrap();
        assert_eq!(&result[result.len() - 2..], &[0, 0]);
        let decoded = String::from_utf16(&result).unwrap();
        assert_eq!(decoded, "PATH=C:\\工具😀\0SYSTEMROOT=C:\\Windows\0TMP=\0\0");
        assert_eq!(encode_environment(&[]).unwrap(), vec![0, 0]);
        for entries in [
            vec![("PATH".into(), "a".into()), ("path".into(), "b".into())],
            vec![("TOKEN".into(), "x".into())],
            vec![("=C:".into(), "x".into())],
            vec![("PA\0TH".into(), "x".into())],
            vec![("PATH".into(), "x\0y".into())],
            vec![("HOME".into(), "x".into())],
            vec![("PATH".into(), "😀".repeat(16_384))],
        ] {
            assert!(encode_environment(&entries).is_err());
        }
    }

    #[test]
    fn cwd_encoder_requires_absolute_non_device_path() {
        for path in [
            "relative",
            "C:relative",
            "C:\\a\\..",
            "\\\\?\\C:\\root",
            "C:\\a\0b",
        ] {
            assert!(encode_cwd(path).is_err());
        }
        assert_eq!(encode_cwd("C:\\").unwrap(), vec![67, 58, 92, 0]);
        assert!(encode_cwd("\\\\server\\share").is_ok());
        assert!(encode_cwd(&format!("C:\\{}", "😀".repeat(16_384))).is_err());
    }

    // Independent CRT-style decoder for the ordinary argument tail. argv[0]
    // is deliberately not decoded with this grammar because CRT treats it specially.
    fn decode_tail(line: &str) -> Vec<String> {
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        let mut result = Vec::new();
        while i < chars.len() {
            while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                i += 1;
            }
            if i == chars.len() {
                break;
            }
            let mut argument = String::new();
            let mut quoted = false;
            while i < chars.len() && (quoted || !matches!(chars[i], ' ' | '\t')) {
                let mut slash_count = 0;
                while i < chars.len() && chars[i] == '\\' {
                    slash_count += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    argument.extend(std::iter::repeat_n('\\', slash_count / 2));
                    if slash_count % 2 == 1 {
                        argument.push('"');
                    } else {
                        quoted = !quoted;
                    }
                    i += 1;
                } else {
                    argument.extend(std::iter::repeat_n('\\', slash_count));
                    if i < chars.len() && (quoted || !matches!(chars[i], ' ' | '\t')) {
                        argument.push(chars[i]);
                        i += 1;
                    }
                }
            }
            result.push(argument);
        }
        result
    }

    #[test]
    fn exact_crt_roundtrip_preserves_empty_unicode_quotes_slashes_and_metacharacters() {
        let alphabet = ["", "a", " ", "\t", "\\", "\"", "😀", "&|<>%^$()", "\n"];
        for left in alphabet {
            for right in alphabet {
                let arguments = vec![format!("{left}{right}"), "tail\\\\".into()];
                let result = encode("C:\\Program Files\\Checker\\tool.exe", &arguments).unwrap();
                let line =
                    String::from_utf16(&result.command_line[..result.command_line.len() - 1])
                        .unwrap();
                let tail = &line[line.find("\" ").unwrap() + 2..];
                assert_eq!(decode_tail(tail), arguments, "{line:?}");
                assert_eq!(result.application.last(), Some(&0));
            }
        }
    }

    #[test]
    fn rejects_discovery_nul_relative_components_and_oversized_utf16() {
        for path in [
            "tool.exe",
            "C:tool.exe",
            "C:\\a\\..\\tool.exe",
            "C:\\tool.cmd",
            "C:\\bad\".exe",
        ] {
            assert!(encode(path, &[]).is_err());
        }
        assert!(encode("C:\\tool.exe", &["a\0b".into()]).is_err());
        assert!(encode("C:\\tool.exe", &["😀".repeat(16_384)]).is_err());
        assert!(encode("\\\\server\\share\\tool.exe", &[]).is_ok());
    }
}
