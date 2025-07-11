// SPDX-License-Identifier: LGPL-2.0-or-later

#![allow(clippy::missing_safety_doc)]
use anyhow::Context as _;
use libc::{c_char, c_int, size_t};
use openpgp::cert::prelude::*;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer};
use openpgp::KeyHandle;
use sequoia_cert_store::{Store as _, StoreUpdate as _};
use sequoia_openpgp as openpgp;
use sequoia_policy_config::ConfiguredStandardPolicy;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::Arc;

use crate::{set_error_from, SequoiaError};

pub struct SequoiaMechanism<'a> {
    keystore: sequoia_keystore::Keystore,
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
    policy: StandardPolicy<'a>,
}

impl<'a> SequoiaMechanism<'a> {
    fn from_directory(dir: Option<impl AsRef<Path>>) -> Result<Self, anyhow::Error> {
        let home_path = dir.map(|s| s.as_ref().to_path_buf());
        let sequoia_home = sequoia_directories::Home::new(home_path)?;

        let keystore_dir = sequoia_home.data_dir(sequoia_directories::Component::Keystore);
        let context = sequoia_keystore::Context::configure()
            .home(&keystore_dir)
            .build()?;
        let keystore = sequoia_keystore::Keystore::connect(&context)?;

        let certstore_dir = sequoia_home.data_dir(sequoia_directories::Component::CertD);
        fs::create_dir_all(&certstore_dir)?;
        let certstore = sequoia_cert_store::CertStore::open(&certstore_dir)?;

        let policy = crypto_policy()?;

        Ok(Self {
            keystore,
            certstore: Arc::new(certstore),
            policy,
        })
    }

    fn ephemeral() -> Result<Self, anyhow::Error> {
        let context = sequoia_keystore::Context::configure().ephemeral().build()?;
        let certstore = Arc::new(sequoia_cert_store::CertStore::empty());
        let policy = crypto_policy()?;
        Ok(Self {
            keystore: sequoia_keystore::Keystore::connect(&context)?,
            certstore,
            policy,
        })
    }

    fn import_keys(&mut self, blob: &[u8]) -> Result<SequoiaImportResult, anyhow::Error> {
        let mut key_handles = vec![];
        for r in CertParser::from_bytes(blob)? {
            let cert = match r {
                Ok(cert) => cert,
                Err(err) => {
                    log::info!("Error reading cert: {err}");
                    continue;
                }
            };

            key_handles.push(CString::new(cert.fingerprint().to_hex().as_bytes()).unwrap());
            self.certstore
                .update(Arc::new(sequoia_cert_store::LazyCert::from(cert)))?;
        }
        Ok(SequoiaImportResult { key_handles })
    }

    fn sign(
        &mut self,
        key_handle: &str,
        password: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let primary_key_handle: KeyHandle = key_handle.parse()?; // FIXME: For gpgme, allow lookup by user ID? grep_userid, or what is the compatible semantics?
        let certs = self
            .certstore
            .lookup_by_cert_or_subkey(&primary_key_handle)
            .with_context(|| format!("Failed to load {key_handle} from certificate store"))?
            .into_iter()
            .filter_map(|cert| match cert.to_cert() { // FIXME: Should this report the error?
                Ok(cert) => Some(cert.clone()),
                Err(_) => None,
            })
            .collect::<Vec<Cert>>();

        let mut signing_key_handles: Vec<KeyHandle> = vec![];
        for cert in certs {
            // FIXME: read from here on
            for ka in cert.keys().with_policy(&self.policy, None).for_signing() {
                signing_key_handles.push(ka.key().fingerprint().into());
            }
        }

        if signing_key_handles.is_empty() {
            return Err(anyhow::anyhow!("No matching signing key for {key_handle}"));
        }

        let mut keys = self.keystore.find_key(signing_key_handles[0].clone())?;

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No matching key in keystore"));
        }
        if let Some(password) = password {
            keys[0].unlock(password.into())?;
        }

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Signer::new(message, &mut keys[0])?.build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(data)?;
            message.finalize()?;
        }
        Ok(sink)
    }

    fn verify(&mut self, signature: &[u8]) -> Result<SequoiaVerificationResult, anyhow::Error> {
        if signature.is_empty() {
            return Err(anyhow::anyhow!("empty signature"));
        }

        let h = Helper {
            certstore: self.certstore.clone(),
            signer: Default::default(),
        };

        let mut v = VerifierBuilder::from_bytes(signature)?.with_policy(&self.policy, None, h)?;
        let mut content = Vec::new();
        v.read_to_end(&mut content)?;

        assert!(v.message_processed());

        match &v.helper_ref().signer {
            Some(signer) => Ok(SequoiaVerificationResult {
                content,
                signer: CString::new(signer.fingerprint().to_hex().as_bytes()).unwrap(),
            }),
            None => Err(anyhow::anyhow!("No valid signer")),
        }
    }
}

struct Helper<'a> {
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
    signer: Option<openpgp::Cert>,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut certs = Vec::new();
        for id in ids {
            let matches = self.certstore.lookup_by_cert_or_subkey(id);
            for lc in matches? {
                certs.push(lc.to_cert()?.clone());
            }
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut signature_errors: Vec<String> = Vec::new();
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo } => log::info!("Compressed using {algo}"),
                MessageLayer::Encryption {
                    sym_algo,
                    aead_algo,
                } => {
                    if let Some(aead_algo) = aead_algo {
                        log::info!("Encrypted and protected using {sym_algo}/{aead_algo}");
                    } else {
                        log::info!("Encrypted using {sym_algo}");
                    }
                }
                MessageLayer::SignatureGroup { ref results } => {
                    for result in results {
                        match result {
                            Ok(good_checksum) => {
                                self.signer = Some(good_checksum.ka.cert().to_owned());
                                return Ok(());
                            }
                            Err(verification_error) => {
                                signature_errors.push(verification_error.to_string());
                            }
                        }
                    }
                }
            }
        }
        let err = match signature_errors.len() {
        0 => anyhow::anyhow!("No valid signature"),
        1 => anyhow::anyhow!("{}", &signature_errors[0]),
        _ => anyhow::anyhow!("Multiple signature errors: [{}]", signature_errors.join(", ")),
        };
        Err(err)
    }
}

/// Creates a StandardPolicy with the policy we desire, primarily based on the system’s configuration.
fn crypto_policy<'a>() -> Result<StandardPolicy<'a>, anyhow::Error> {
    let mut policy = ConfiguredStandardPolicy::new();
    policy.parse_default_config()?;
    Ok(policy.build())
}

pub struct SequoiaSignature {
    data: Vec<u8>,
}

pub struct SequoiaVerificationResult {
    content: Vec<u8>,
    signer: CString,
}

#[derive(Default)]
pub struct SequoiaImportResult {
    key_handles: Vec<CString>,
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_new_from_directory<'a>(
    dir_ptr: *const c_char,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaMechanism<'a> {
    let c_dir = if dir_ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(dir_ptr))
    };
    let os_dir = c_dir.map(|s| OsStr::from_bytes(s.to_bytes()));
    match SequoiaMechanism::from_directory(os_dir) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_new_ephemeral<'a>(
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaMechanism<'a> {
    match SequoiaMechanism::ephemeral() {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_free(mechanism_ptr: *mut SequoiaMechanism) {
    drop(Box::from_raw(mechanism_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_signature_free(signature_ptr: *mut SequoiaSignature) {
    drop(Box::from_raw(signature_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_signature_get_data(
    signature_ptr: *const SequoiaSignature,
    data_len: *mut size_t,
) -> *const u8 {
    assert!(!signature_ptr.is_null());
    *data_len = (*signature_ptr).data.len();
    (*signature_ptr).data.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_free(
    result_ptr: *mut SequoiaVerificationResult,
) {
    assert!(!result_ptr.is_null());
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_get_content(
    result_ptr: *const SequoiaVerificationResult,
    data_len: *mut size_t,
) -> *const u8 {
    assert!(!result_ptr.is_null());
    *data_len = (*result_ptr).content.len();
    (*result_ptr).content.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_get_signer(
    result_ptr: *const SequoiaVerificationResult,
) -> *const c_char {
    assert!(!result_ptr.is_null());
    (*result_ptr).signer.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_sign(
    mechanism_ptr: *mut SequoiaMechanism,
    key_handle_ptr: *const c_char,
    password_ptr: *const c_char,
    data_ptr: *const u8,
    data_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaSignature {
    assert!(!mechanism_ptr.is_null());
    assert!(!key_handle_ptr.is_null());
    assert!(!data_ptr.is_null());

    let key_handle = match CStr::from_ptr(key_handle_ptr).to_str() {
        Ok(key_handle) => key_handle,
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    };

    let password = if password_ptr.is_null() {
        None
    } else {
        match CStr::from_ptr(password_ptr).to_str() {
            Ok(password) => Some(password),
            Err(e) => {
                set_error_from(err_ptr, e.into());
                return ptr::null_mut();
            }
        }
    };

    let data = slice::from_raw_parts(data_ptr, data_len);
    match (*mechanism_ptr).sign(key_handle, password, data) {
        Ok(signature) => Box::into_raw(Box::new(SequoiaSignature { data: signature })),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verify(
    mechanism_ptr: *mut SequoiaMechanism,
    signature_ptr: *const u8,
    signature_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaVerificationResult {
    assert!(!mechanism_ptr.is_null());

    let signature = slice::from_raw_parts(signature_ptr, signature_len);
    match (*mechanism_ptr).verify(signature) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_free(result_ptr: *mut SequoiaImportResult) {
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_get_count(
    result_ptr: *const SequoiaImportResult,
) -> size_t {
    assert!(!result_ptr.is_null());

    (*result_ptr).key_handles.len()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_get_content(
    result_ptr: *const SequoiaImportResult,
    index: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *const c_char {
    assert!(!result_ptr.is_null());

    if index >= (*result_ptr).key_handles.len() {
        set_error_from(err_ptr, anyhow::anyhow!("No matching key handle"));
        return ptr::null();
    }
    let key_handle = &(&(*result_ptr)).key_handles[index];
    key_handle.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_keys(
    mechanism_ptr: *mut SequoiaMechanism,
    blob_ptr: *const u8,
    blob_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaImportResult {
    assert!(!mechanism_ptr.is_null());

    let blob = slice::from_raw_parts(blob_ptr, blob_len);
    if blob.is_empty() {
        let result = SequoiaImportResult {
            ..Default::default()
        };
        return Box::into_raw(Box::new(result));
    }

    match (*mechanism_ptr).import_keys(blob) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

// SequoiaLogLevel is a C-compatible version of log::Level.
#[repr(C)]
pub enum SequoiaLogLevel {
    SequoiaLogLevelUnknown,
    SequoiaLogLevelError,
    SequoiaLogLevelWarn,
    SequoiaLogLevelInfo,
    SequoiaLogLevelDebug,
    SequoiaLogLevelTrace,
}

// SequoiaLogger implements log::Log.
struct SequoiaLogger {
    consumer: unsafe extern "C" fn(level: SequoiaLogLevel, message: *const c_char),
}

impl log::Log for SequoiaLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            log::Level::Error => SequoiaLogLevel::SequoiaLogLevelError,
            log::Level::Warn => SequoiaLogLevel::SequoiaLogLevelWarn,
            log::Level::Info => SequoiaLogLevel::SequoiaLogLevelInfo,
            log::Level::Debug => SequoiaLogLevel::SequoiaLogLevelDebug,
            log::Level::Trace => SequoiaLogLevel::SequoiaLogLevelTrace,
        };
        let text = match CString::new(record.args().to_string()) {
            Ok(text) => text,
            Err(_) => {
                return;
            }
        };
        unsafe {
            (self.consumer)(level, text.as_ptr())
        };
    }

    fn flush(&self) {}
}

// sequoia_set_logger_consumer sets the process-wide Rust logger to the provided simple string consumer.
// More sophisticated logging interfaces may be added in the future as an alternative.
// Note that the logger is a per-process global; it is up to the caller to coordinate.
#[no_mangle]
pub unsafe extern "C" fn sequoia_set_logger_consumer(
    consumer: unsafe extern "C" fn(level: SequoiaLogLevel, message: *const c_char),
    err_ptr: *mut *mut SequoiaError
) -> c_int {
    let logger = SequoiaLogger { consumer };
    match log::set_boxed_logger(Box::new(logger)) { // Leaks the logger, but this is explicitly an once-per-process API.
        Ok(_) => {},
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return -1
        }
    }

    log::set_max_level(log::LevelFilter::Trace); // We’ll let the consumer do the filtering, if any.
    0
}
