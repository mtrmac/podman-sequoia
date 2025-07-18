// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)]
use libc::c_char;
use std::ffi::CString;
use std::io;

#[derive(Eq, PartialEq, Debug)]
#[repr(C)]
/// cbindgen:rename-all=ScreamingSnakeCase
/// cbindgen:prefix-with-name
pub enum SequoiaErrorKind {
    Unknown,
    InvalidArgument,
    IoError,
}

#[derive(Debug)]
#[repr(C)]
pub struct SequoiaError {
    pub kind: SequoiaErrorKind,
    pub message: *mut c_char,
}

impl Drop for SequoiaError {
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.message);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_error_free(err_ptr: *mut SequoiaError) {
    drop(Box::from_raw(err_ptr))
}

pub unsafe fn set_error_from(err_ptr: *mut *mut SequoiaError, err: anyhow::Error) {
    if !err_ptr.is_null() {
        let kind = if err.is::<io::Error>() {
            SequoiaErrorKind::IoError
        } else {
            SequoiaErrorKind::Unknown
        };

        *err_ptr = Box::into_raw(Box::new(SequoiaError {
            kind,
            message: CString::from_vec_unchecked(err.to_string().into()).into_raw(),
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_usage() {
        let error_text = "test error";
        let result = Result::<(), anyhow::Error>::Err(anyhow::anyhow!(error_text));
        let mut err_ptr: *mut SequoiaError = std::ptr::null_mut();
        unsafe { set_error_from(&mut err_ptr, result.unwrap_err()) }
        assert!(!err_ptr.is_null());
        unsafe {
            assert_eq!((*err_ptr).kind, SequoiaErrorKind::Unknown);
            assert_eq!(
                std::ffi::CStr::from_ptr((*err_ptr).message).to_str(),
                Ok(error_text)
            );
        }
        unsafe { sequoia_error_free(err_ptr) }
    }

    #[test]
    fn nil_destination() {
        let result = Result::<(), anyhow::Error>::Err(anyhow::anyhow!("test error"));
        unsafe { set_error_from(std::ptr::null_mut(), result.unwrap_err()) }
    }

    #[test]
    fn io_error() {
        let error_text = "test error";
        let result = Result::<(), anyhow::Error>::Err(
            io::Error::new(io::ErrorKind::Other, error_text).into(),
        );
        let mut err_ptr: *mut SequoiaError = std::ptr::null_mut();
        unsafe { set_error_from(&mut err_ptr, result.unwrap_err()) }
        assert!(!err_ptr.is_null());
        unsafe {
            assert_eq!((*err_ptr).kind, SequoiaErrorKind::IoError);
            assert_eq!(
                std::ffi::CStr::from_ptr((*err_ptr).message).to_str(),
                Ok(error_text)
            );
        }
        unsafe { sequoia_error_free(err_ptr) }
    }
}
