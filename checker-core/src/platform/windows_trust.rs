//! Conservative native Windows executable installation trust audit.
//! Every file and ancestor is held against write/delete sharing and audited by
//! handle. Unknown ACE formats, null DACLs, reparse points and non-system owners
//! fail closed. This is deliberately narrower than general Windows ACL access.
//! Default Windows volume/root ACLs can grant ordinary users creation rights;
//! this conservative policy may refuse those installations. Native fixtures must
//! establish a usable trusted-root policy before platform support is enabled.
//! Passing this audit does not discover transitive DLLs or constrain DLL search:
//! those remain separate runtime-closure and restricted-launch requirements.
//! https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
//! https://learn.microsoft.com/en-us/windows/win32/secauthz/ace

// Deliberately ignore deny ACE ordering as a justification for broad allows.
// This over-approximates mutation rights and can reject safe complex ACLs.
fn trusted_principal(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}
fn allow_is_immutable(mask: u32, sid: &str) -> bool {
    let mutation = 0x0000_0156 | 0x000d_0000 | 0x0200_0000 | 0x5000_0000;
    mask & mutation == 0 || trusted_principal(sid)
}

#[cfg(windows)]
mod native {
    use crate::platform::windows_ffi::{
        AceHeader, ConvertSidToStringSidW, CreateFileW, GetAce, GetFileInformationByHandle,
        GetLengthSid, GetSecurityInfo, Handle, IsValidAcl, IsValidSid, LocalFree,
    };
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::Path,
    };
    struct Allocation(Handle);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn sid_text(sid: Handle) -> Result<String, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err("invalid installation SID".into());
        }
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err("installation SID unavailable".into());
        }
        let _allocation = Allocation(text.cast());
        let mut len = 0;
        while len < 256 && unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        if len == 256 {
            return Err("installation SID exceeds limit".into());
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
            .map_err(|_| "invalid installation SID encoding".into())
    }
    fn audit(file: &OwnedHandle) -> Result<(), String> {
        let mut info = [0_u32; 13];
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr().cast()) }
            == 0
        {
            return Err("installation file identity unavailable".into());
        }
        if info[0] & 0x400 != 0 {
            return Err("installation reparse points are unsupported".into());
        }
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                1,
                1 | 4,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        } != 0
        {
            return Err("installation security descriptor unavailable".into());
        }
        let _descriptor = Allocation(descriptor);
        if !super::trusted_principal(&sid_text(owner)?) {
            return Err("installation owner is not a trusted system principal".into());
        }
        if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return Err("installation DACL absent or invalid".into());
        }
        let count = unsafe { (*acl).count };
        if count > 1024 {
            return Err("installation DACL exceeds limit".into());
        }
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
                return Err("installation ACE unavailable".into());
            }
            let header = unsafe { &*ace.cast::<AceHeader>() };
            // Reject callback/object/conditional ACEs; evaluating their semantics
            // requires a complete AccessCheck policy, not an owner shortcut.
            if !matches!(header.kind, 0 | 1) || header.size < 16 {
                return Err("ambiguous installation ACE format".into());
            }
            if header.kind == 1 {
                continue;
            } // Ignore denies; never use them to justify a broad allow.
            let mask = unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()) };
            let sid = unsafe { ace.cast::<u8>().add(8).cast::<c_void>() };
            let sid_size = 8 + 4 * usize::from(unsafe { *ace.cast::<u8>().add(9) });
            if sid_size > usize::from(header.size) - 8
                || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != sid_size
            {
                return Err("malformed installation ACE SID".into());
            }
            // File data/append/EA/attributes/delete-child, DELETE, WRITE_DAC,
            // WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_WRITE and GENERIC_ALL.
            if !super::allow_is_immutable(mask, &sid_text(sid)?) {
                return Err("installation grants mutation rights to an untrusted principal".into());
            }
        }
        Ok(())
    }
    /// Retain this guard with RuntimeManifest through the child lifetime.
    /// Trust is relative to non-administrator attackers; elevated administrators
    /// can take ownership and are explicitly outside this boundary.
    pub struct InstallationTrustGuard {
        handles: Vec<OwnedHandle>,
    }
    impl InstallationTrustGuard {
        pub fn audit(path: &Path) -> Result<Self, String> {
            if !path.is_absolute() {
                return Err("installation path must be absolute".into());
            }
            let mut handles = Vec::new();
            let ancestors: Vec<_> = path.ancestors().collect();
            // Lock parents first so later opens cannot traverse a swapped ancestor.
            for ancestor in ancestors.into_iter().rev() {
                if ancestor.as_os_str().is_empty() {
                    continue;
                }
                if handles.len() >= 256 {
                    return Err("installation ancestor limit exceeded".into());
                }
                let wide: Vec<_> = ancestor.as_os_str().encode_wide().chain(Some(0)).collect();
                if wide[..wide.len() - 1].contains(&0) {
                    return Err("invalid installation path".into());
                }
                let raw = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        0x0002_0080,
                        1,
                        std::ptr::null(),
                        3,
                        0x0220_0000,
                        std::ptr::null_mut(),
                    )
                };
                if raw == -1isize as Handle {
                    return Err("installation path cannot be locked for audit".into());
                }
                let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
                audit(&handle)?;
                handles.push(handle);
            }
            Ok(Self { handles })
        }
        pub fn revalidate(&self) -> Result<(), String> {
            for handle in &self.handles {
                audit(handle)?;
            }
            Ok(())
        }
    }
}
#[cfg(windows)]
pub use native::InstallationTrustGuard;

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn outsider_mutation_allow_masks_are_rejected_individually() {
        let outsider = "S-1-5-21-1-2-3-1001";
        for mask in [
            2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x02000000, 0x10000000, 0x40000000,
        ] {
            assert!(!allow_is_immutable(mask, outsider), "mask {mask:#x}");
        }
        // FILE_GENERIC_READ/EXECUTE without mutation rights.
        assert!(allow_is_immutable(0x001200a9, outsider));
        // ALL APPLICATION PACKAGES is never a trusted mutation principal.
        assert!(!allow_is_immutable(0x10000000, "S-1-15-2-1"));
    }
    #[test]
    fn privileged_owner_does_not_justify_outsider_write_ace() {
        assert!(trusted_principal("S-1-5-18"));
        assert!(!allow_is_immutable(0x40000, "S-1-1-0"));
        assert!(!trusted_principal("S-1-5-21-1-2-3-1001"));
        assert!(allow_is_immutable(0x10000000, "S-1-5-32-544"));
    }
}
