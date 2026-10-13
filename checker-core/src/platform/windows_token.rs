//! Experimental LPAC creation attributes, not a qualified launch policy.
//! No process creation, privilege escalation, ACL mutation, or broad fallback.
//! Sources consulted 2026-10-12:
//! https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
//! https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername
//! https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

fn validate_profile_name(name: &str) -> std::io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AppContainer identity must be 1..64 ASCII letters, digits, dot, dash or underscore",
        ));
    }
    Ok(())
}

fn validate_stdio_values(handles: [usize; 3]) -> std::io::Result<()> {
    if handles
        .iter()
        .any(|value| *value == 0 || (*value as isize) < 0)
        || handles[0] == handles[1]
        || handles[0] == handles[2]
        || handles[1] == handles[2]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "exactly three distinct non-pseudo stdio handles required",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn unavailable() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "LPAC security attributes require native Windows",
    )
}

#[cfg(target_os = "windows")]
pub use native::LpacAttributes;

#[cfg(target_os = "windows")]
mod native {
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::ptr::{NonNull, null_mut};

    const SECURITY_CAPABILITIES: usize = 0x00020009;
    const ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002000f;
    const OPT_OUT: u32 = 1;
    const HANDLE_LIST: usize = 0x00020002;
    const INSUFFICIENT_BUFFER: i32 = 122;

    #[repr(C)]
    struct SecurityCapabilities {
        sid: *mut c_void,
        capabilities: *mut c_void,
        count: u32,
        reserved: u32,
    }

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn DeriveAppContainerSidFromAppContainerName(
            name: *const u16,
            sid: *mut *mut c_void,
        ) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn FreeSid(sid: *mut c_void) -> *mut c_void;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: u32,
            flags: u32,
            bytes: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *mut c_void,
            bytes: usize,
            previous: *mut c_void,
            returned: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(list: *mut c_void);
        fn GetProcessHeap() -> *mut c_void;
        fn HeapAlloc(heap: *mut c_void, flags: u32, bytes: usize) -> *mut c_void;
        fn HeapFree(heap: *mut c_void, flags: u32, memory: *mut c_void) -> i32;
    }
    struct Sid(NonNull<c_void>);
    impl Drop for Sid {
        fn drop(&mut self) {
            unsafe {
                FreeSid(self.0.as_ptr());
            }
        }
    }
    struct AttributeList {
        pointer: NonNull<c_void>,
        heap: NonNull<c_void>,
        initialized: bool,
    }
    impl Drop for AttributeList {
        fn drop(&mut self) {
            unsafe {
                if self.initialized {
                    DeleteProcThreadAttributeList(self.pointer.as_ptr());
                }
                HeapFree(self.heap.as_ptr(), 0, self.pointer.as_ptr());
            }
        }
    }

    /// Stable backing storage for zero-capability least-privilege AppContainer
    /// attributes. Not Send/Sync. Caller owns profile/ACL lifecycle separately.
    pub struct LpacAttributes {
        // Drop list before attribute values and SID it references.
        list: AttributeList,
        capabilities: Box<SecurityCapabilities>,
        opt_out: Box<u32>,
        sid: Sid,
        inherited_handles: Option<Box<[*mut c_void]>>,
    }
    impl LpacAttributes {
        /// Derive a trusted broker-selected profile identity. Does NOT create a
        /// profile or prove its ACL/network exemptions safe; never accept a
        /// project-supplied identity that could reuse prior granted resources.
        pub fn for_profile_name(name: &str) -> io::Result<Self> {
            super::validate_profile_name(name)?;
            let encoded: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut raw_sid = null_mut();
            let hr = unsafe {
                DeriveAppContainerSidFromAppContainerName(encoded.as_ptr(), &mut raw_sid)
            };
            if hr < 0 {
                return Err(io::Error::other(format!(
                    "AppContainer SID derivation failed: HRESULT {hr:#x}"
                )));
            }
            let sid = Sid(NonNull::new(raw_sid).ok_or_else(|| {
                io::Error::other("AppContainer SID derivation returned no identity")
            })?);
            let mut bytes = 0;
            let initial =
                unsafe { InitializeProcThreadAttributeList(null_mut(), 3, 0, &mut bytes) };
            if initial != 0
                || io::Error::last_os_error().raw_os_error() != Some(INSUFFICIENT_BUFFER)
                || bytes == 0
            {
                return Err(io::Error::other(
                    "unexpected LPAC attribute-list sizing result",
                ));
            }
            let heap =
                NonNull::new(unsafe { GetProcessHeap() }).ok_or_else(io::Error::last_os_error)?;
            let pointer = NonNull::new(unsafe { HeapAlloc(heap.as_ptr(), 0, bytes) })
                .ok_or_else(|| io::Error::other("LPAC attribute allocation failed"))?;
            let mut list = AttributeList {
                pointer,
                heap,
                initialized: false,
            };
            if unsafe { InitializeProcThreadAttributeList(pointer.as_ptr(), 3, 0, &mut bytes) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            list.initialized = true;
            let capabilities = Box::new(SecurityCapabilities {
                sid: sid.0.as_ptr(),
                capabilities: null_mut(),
                count: 0,
                reserved: 0,
            });
            let opt_out = Box::new(OPT_OUT);
            // Bundle before registration so failure paths delete the attribute
            // list while every registered value is still alive.
            let mut result = Self {
                list,
                capabilities,
                opt_out,
                sid,
                inherited_handles: None,
            };
            if unsafe {
                UpdateProcThreadAttribute(
                    pointer.as_ptr(),
                    0,
                    SECURITY_CAPABILITIES,
                    (&mut *result.capabilities as *mut SecurityCapabilities).cast(),
                    size_of::<SecurityCapabilities>(),
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe {
                UpdateProcThreadAttribute(
                    pointer.as_ptr(),
                    0,
                    ALL_APPLICATION_PACKAGES_POLICY,
                    (&mut *result.opt_out as *mut u32).cast(),
                    size_of::<u32>(),
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(result)
        }

        /// Native adapter may borrow this only for CreateProcessW with
        /// EXTENDED_STARTUPINFO_PRESENT. Never mutate/delete/retain this list.
        /// This list intentionally lacks HANDLE_LIST: until the launch adapter
        /// adds an owned third attribute, CreateProcessW must use inherit=FALSE.
        pub fn as_ptr(&self) -> *mut c_void {
            self.list.pointer.as_ptr()
        }

        /// Add exactly three inherited stdio handles to the same LPAC list.
        /// # Safety
        /// All handles must be distinct, valid, inheritable, broker-owned and
        /// retained until process creation returns. They cannot access state.
        pub(crate) unsafe fn set_stdio_handles(
            &mut self,
            handles: [*mut c_void; 3],
        ) -> io::Result<()> {
            super::validate_stdio_values(handles.map(|h| h as usize))?;
            if self.inherited_handles.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exactly three distinct owned stdio handles required",
                ));
            }
            self.inherited_handles = Some(Box::new(handles));
            let list = self
                .inherited_handles
                .as_mut()
                .expect("handle backing installed");
            if unsafe {
                UpdateProcThreadAttribute(
                    self.list.pointer.as_ptr(),
                    0,
                    HANDLE_LIST,
                    list.as_mut_ptr().cast(),
                    size_of::<[*mut c_void; 3]>(),
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// ACL construction must use this exact identity, with explicit narrowly
        /// scoped permissions; never grant ALL_APPLICATION_PACKAGES access.
        pub fn sid_ptr(&self) -> *mut c_void {
            self.sid.0.as_ptr()
        }

        pub fn network_capability_count(&self) -> u32 {
            let _ = &self.opt_out;
            self.capabilities.count
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stdio_values_reject_missing_pseudo_and_aliasing_before_native_calls() {
        for values in [
            [0, 4, 8],
            [4, 0, 8],
            [4, 8, 0],
            [4, 4, 8],
            [4, 8, 4],
            [4, 8, 8],
            [usize::MAX, 4, 8],
            [4, usize::MAX - 1, 8],
        ] {
            assert!(super::validate_stdio_values(values).is_err());
        }
        assert!(super::validate_stdio_values([4, 8, 12]).is_ok());
        // Numeric validation is NOT handle ownership/liveness qualification.
    }
    #[test]
    fn identity_validation_excludes_nul_unicode_and_path_separators() {
        for invalid in ["", "../x", "name\\x", "name\0x", "námé"] {
            assert!(
                super::validate_profile_name(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(super::validate_profile_name("checker.run-0123").is_ok());
        assert!(super::validate_profile_name(&"x".repeat(65)).is_err());
    }
}
