//! Shared Win32 ABI declarations for candidate platform primitives.
//! No policy or authorization is implemented here. Callers own all lifetimes.
//! https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-security_attributes
//! https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
//! https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
//! https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information

#![cfg(windows)]
#![allow(non_snake_case)]

use std::ffi::c_void;
pub type Handle = *mut c_void;

#[repr(C)]
pub struct SecurityAttributes {
    pub length: u32,
    pub descriptor: Handle,
    pub inherit: i32,
}

#[repr(C)]
pub struct Acl {
    pub revision: u8,
    pub reserved: u8,
    pub size: u16,
    pub count: u16,
    pub reserved2: u16,
}

#[repr(C)]
pub struct AceHeader {
    pub kind: u8,
    pub flags: u8,
    pub size: u16,
}

/// Thirteen DWORD fields: attributes; three FILETIMEs; volume serial;
/// file-size high/low; link count; file-index high/low. Layout is 52 bytes.
#[repr(C)]
pub struct FileInformation {
    pub values: [u32; 13],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn CreateFileW(
        path: *const u16,
        access: u32,
        sharing: u32,
        security: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    // Untyped output preserves the native LPBY_HANDLE_FILE_INFORMATION ABI
    // while callers may use FileInformation or a correctly sized DWORD array.
    pub fn GetFileInformationByHandle(file: Handle, information: *mut c_void) -> i32;
    pub fn SetFileInformationByHandle(
        file: Handle,
        class: u32,
        info: *mut c_void,
        bytes: u32,
    ) -> i32;
    pub fn LocalFree(allocation: Handle) -> Handle;
    pub fn GetCurrentProcess() -> Handle;
    pub fn GetCurrentThread() -> Handle;
    pub fn ReadFile(
        file: Handle,
        data: *mut c_void,
        bytes: u32,
        read: *mut u32,
        overlapped: Handle,
    ) -> i32;
    pub fn WriteFile(
        file: Handle,
        data: *const c_void,
        bytes: u32,
        written: *mut u32,
        overlapped: Handle,
    ) -> i32;
    pub fn FlushFileBuffers(file: Handle) -> i32;
    pub fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn GetSecurityInfo(
        object: Handle,
        kind: u32,
        requested: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut *mut Acl,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    pub fn GetAce(acl: *mut Acl, index: u32, ace: *mut Handle) -> i32;
    pub fn IsValidAcl(acl: *mut Acl) -> i32;
    pub fn IsValidSid(sid: Handle) -> i32;
    pub fn GetLengthSid(sid: Handle) -> u32;
    pub fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        bytes: *mut u32,
    ) -> i32;
    pub fn GetSecurityDescriptorDacl(
        descriptor: Handle,
        present: *mut i32,
        dacl: *mut *mut Acl,
        defaulted: *mut i32,
    ) -> i32;
    pub fn SetSecurityInfo(
        object: Handle,
        kind: u32,
        requested: u32,
        owner: Handle,
        group: Handle,
        dacl: *mut Acl,
        sacl: *mut Acl,
    ) -> u32;
    pub fn SetNamedSecurityInfoW(
        name: *mut u16,
        kind: u32,
        requested: u32,
        owner: Handle,
        group: Handle,
        dacl: *mut Acl,
        sacl: *mut Acl,
    ) -> u32;
    pub fn GetSecurityDescriptorControl(
        descriptor: Handle,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    pub fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    pub fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        size: u32,
        required: *mut u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_struct_layout_matches_windows_sdk() {
        assert_eq!(std::mem::size_of::<Acl>(), 8);
        assert_eq!(std::mem::size_of::<AceHeader>(), 4);
        assert_eq!(std::mem::size_of::<FileInformation>(), 52);
        let expected = if std::mem::size_of::<usize>() == 8 {
            24
        } else {
            12
        };
        assert_eq!(std::mem::size_of::<SecurityAttributes>(), expected);
    }
}
