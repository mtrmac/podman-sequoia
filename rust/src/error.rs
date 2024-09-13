// SPDX-License-Identifier: LGPL-2.0-or-later

use libc::c_char;
use std::ffi::CString;
use std::io;

#[repr(C)]
pub enum OpenpgpErrorKind {
    Unknown,
    InvalidArgument,
    IoError,
}

#[repr(C)]
pub struct OpenpgpError {
    kind: OpenpgpErrorKind,
    message: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_error_free(err_ptr: *mut OpenpgpError) {
    drop(Box::from_raw(err_ptr))
}

pub fn set_error(err_ptr: *mut *mut OpenpgpError, kind: OpenpgpErrorKind, message: &str) {
    if !err_ptr.is_null() {
        unsafe {
            *err_ptr = Box::into_raw(Box::new(OpenpgpError {
                kind,
                message: CString::new(message).unwrap().into_raw(),
            }));
        }
    }
}

pub fn set_error_from(err_ptr: *mut *mut OpenpgpError, err: anyhow::Error) {
    if !err_ptr.is_null() {
        let kind = if err.is::<io::Error>() {
            OpenpgpErrorKind::IoError
        } else {
            OpenpgpErrorKind::Unknown
        };

        unsafe {
            *err_ptr = Box::into_raw(Box::new(OpenpgpError {
                kind,
                message: CString::from_vec_unchecked(err.to_string().into()).into_raw(),
            }));
        }
    }
}
