// SPDX-License-Identifier: Apache-2.0

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
    keystore: Option<sequoia_keystore::Keystore>,
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
            keystore: Some(keystore),
            certstore: Arc::new(certstore),
            policy,
        })
    }

    fn ephemeral() -> Result<Self, anyhow::Error> {
        let certstore = Arc::new(sequoia_cert_store::CertStore::empty());
        let policy = crypto_policy()?;
        Ok(Self {
            keystore: None,
            certstore,
            policy,
        })
    }

    fn import_keys(&mut self, blob: &[u8]) -> Result<SequoiaImportResult, anyhow::Error> {
        let mut key_handles = vec![];
        for r in CertParser::from_bytes(blob)? {
            // NOTE that we might have successfully imported something by now;
            // in that case we just return an error and don't report what we have imported.
            // That's fine for containers/image, which creates an one-use ephemeral mechanism
            // and imports keys into it, i.e. there is no benefit in handling partial success specially.
            let cert = r.context("Error parsing certificate")?;

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
            .filter_map(|cert| match cert.to_cert() {
                // FIXME: Should this report the error?
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

        let keystore = self.keystore.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Caller error: attempting to sign with an ephemeral mechanism")
        })?;
        let mut keys = keystore.find_key(signing_key_handles[0].clone())?;

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
            _ => anyhow::anyhow!(
                "Multiple signature errors: [{}]",
                signature_errors.join(", ")
            ),
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
/// cbindgen:rename-all=ScreamingSnakeCase
/// cbindgen:prefix-with-name
pub enum SequoiaLogLevel {
    Unknown,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
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
            log::Level::Error => SequoiaLogLevel::Error,
            log::Level::Warn => SequoiaLogLevel::Warn,
            log::Level::Info => SequoiaLogLevel::Info,
            log::Level::Debug => SequoiaLogLevel::Debug,
            log::Level::Trace => SequoiaLogLevel::Trace,
        };
        let text = match CString::new(record.args().to_string()) {
            Ok(text) => text,
            Err(_) => {
                return;
            }
        };
        unsafe { (self.consumer)(level, text.as_ptr()) };
    }

    fn flush(&self) {}
}

// sequoia_set_logger_consumer sets the process-wide Rust logger to the provided simple string consumer.
// More sophisticated logging interfaces may be added in the future as an alternative.
// Note that the logger is a per-process global; it is up to the caller to coordinate.
#[no_mangle]
pub unsafe extern "C" fn sequoia_set_logger_consumer(
    consumer: unsafe extern "C" fn(level: SequoiaLogLevel, message: *const c_char),
    err_ptr: *mut *mut SequoiaError,
) -> c_int {
    let logger = SequoiaLogger { consumer };
    match log::set_boxed_logger(Box::new(logger)) {
        // Leaks the logger, but this is explicitly an once-per-process API.
        Ok(_) => {}
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return -1;
        }
    }

    log::set_max_level(log::LevelFilter::Trace); // We’ll let the consumer do the filtering, if any.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_FINGERPRINT: &str = "50DDE898DF4E48755C8C2B7AF6F908B6FA48A229";
    const TEST_KEY_FINGERPRINT_WITH_PASSPHRASE: &str = "1F5825285B785E1DB13BF36D2D11A19ABA41C6AE";
    const INVALID_PUBLIC_KEY_BLOB: &[u8] = b"\xC6\x09this is not a valid public key";

    #[test]
    fn primary_workflow() {
        // The typical successful usage of this library.
        let input = b"Hello, world!";

        let mut err_ptr: *mut SequoiaError = ptr::null_mut();

        let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("./src/data");
        let signed: Vec<u8>;
        {
            let c_sequoia_home = CString::new(fixture_dir.as_os_str().as_bytes()).unwrap();
            let m1 = unsafe {
                sequoia_mechanism_new_from_directory(c_sequoia_home.as_ptr(), &mut err_ptr)
            };
            assert!(!m1.is_null());
            assert!(err_ptr.is_null());

            {
                let c_fingerprint = CString::new(TEST_KEY_FINGERPRINT).unwrap();
                let sig = unsafe {
                    sequoia_sign(
                        m1,
                        c_fingerprint.as_ptr(),
                        std::ptr::null(),
                        input.as_ptr(),
                        input.len(),
                        &mut err_ptr,
                    )
                };
                assert!(!sig.is_null());
                assert!(err_ptr.is_null());
                let mut sig_size: size_t = 0;
                let c_sig_data = unsafe { sequoia_signature_get_data(sig, &mut sig_size) };
                let sig_slice = unsafe { std::slice::from_raw_parts(c_sig_data, sig_size) };
                signed = sig_slice.to_vec();
                unsafe { sequoia_signature_free(sig) };
            }

            unsafe { sequoia_mechanism_free(m1) }
        }

        with_c_ephemeral_mechanism(|m2| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            // With no public key, verification should fail
            let res = unsafe { sequoia_verify(m2, signed.as_ptr(), signed.len(), &mut err_ptr) };
            assert!(res.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
            err_ptr = ptr::null_mut();

            let public_key = include_bytes!("./data/no-passphrase.pub");
            let mut fingerprints: Vec<String> = Vec::new();
            {
                let import_result = unsafe {
                    super::sequoia_import_keys(
                        m2,
                        public_key.as_ptr(),
                        public_key.len(),
                        &mut err_ptr,
                    )
                };
                assert!(!import_result.is_null());
                assert!(err_ptr.is_null());
                let count = unsafe { sequoia_import_result_get_count(import_result) };
                for i in 0..count {
                    let c_fingerprint = unsafe {
                        super::sequoia_import_result_get_content(import_result, i, &mut err_ptr)
                    };
                    let fingerprint = unsafe { CStr::from_ptr(c_fingerprint) };
                    fingerprints.push(fingerprint.to_str().unwrap().to_owned());
                }
                unsafe { sequoia_import_result_free(import_result) };
            }
            assert_eq!(fingerprints.len(), 1);
            assert_eq!(fingerprints[0], TEST_KEY_FINGERPRINT);

            {
                let res =
                    unsafe { sequoia_verify(m2, signed.as_ptr(), signed.len(), &mut err_ptr) };
                assert!(!res.is_null());
                assert!(err_ptr.is_null());

                let mut contents_size: size_t = 0;
                let c_contents =
                    unsafe { sequoia_verification_result_get_content(res, &mut contents_size) };
                let contents_slice =
                    unsafe { std::slice::from_raw_parts(c_contents, contents_size) };
                assert_eq!(contents_slice, input);

                let c_signer = unsafe { sequoia_verification_result_get_signer(res) };
                let signer = unsafe { CStr::from_ptr(c_signer) };
                assert_eq!(signer.to_str().unwrap(), TEST_KEY_FINGERPRINT);

                unsafe { sequoia_verification_result_free(res) };
            }
        });
    }

    #[test]
    fn import_keys() {
        // The basic case of import of a single key is tested in primary_workflow().

        // Empty input.
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(&[]);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().key_handles, []);

        // A valid import of multiple keys.
        let pk1 = include_bytes!("./data/no-passphrase.pub");
        let pk2 = include_bytes!("./data/with-passphrase.pub");
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(&[pk1.as_slice(), pk2.as_slice()].concat());
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().key_handles,
            [
                CString::new(TEST_KEY_FINGERPRINT).unwrap(),
                CString::new(TEST_KEY_FINGERPRINT_WITH_PASSPHRASE).unwrap(),
            ],
        );

        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(b"this is not a valid public key");
        // "unexpected EOF": When the input does not look like binary OpenPGP, the code tries to parse it as ASCII-armored,
        // and looks for a BEGIN… header.
        assert!(res.is_err());

        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(INVALID_PUBLIC_KEY_BLOB);
        // "Error parsing certificate" Malformed packet: Truncated packet": The input starts with a valid enough OpenPGP packet header.
        assert!(res.is_err());

        // Generally, the certstore.update call should never fail for ephemeral mechanisms; it might fail
        // - if the provided LazyCert can’t be parsed, but we already have a parsed form
        // - on an internal inconsistency of CertStore, if it tries to merge two certificates with different fingerprints
        // but, purely for test purposes, we can trigger a write failure by using a non-ephemeral mechanism
        // (which is not expected to happen in practice).
        if cfg!(unix) {
            let sequoia_home = tempfile::tempdir().unwrap();
            let certstore_dir = sequoia_directories::Home::new(sequoia_home.path().to_path_buf())
                .unwrap()
                .data_dir(sequoia_directories::Component::CertD);
            let mut mech = SequoiaMechanism::from_directory(Some(sequoia_home.path())).unwrap();
            // Forcefully delete the contents of certstore_dir, and replace it with a dangling symlink.
            fs::remove_dir_all(&certstore_dir).unwrap();
            std::os::unix::fs::symlink("/var/empty/this/does/not/exist", &certstore_dir).unwrap();
            let res = mech.import_keys(pk1);
            assert!(res.is_err());
        }
    }

    #[test]
    fn sequoia_import_result_get_content() {
        // Success is tested in primary_workflow().

        // Index out of range
        with_c_ephemeral_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let no_public_key = b"";
            let import_result = unsafe {
                super::sequoia_import_keys(
                    m,
                    no_public_key.as_ptr(),
                    no_public_key.len(),
                    &mut err_ptr,
                )
            };
            assert!(!import_result.is_null());
            assert!(err_ptr.is_null());
            let count = unsafe { sequoia_import_result_get_count(import_result) };
            assert_eq!(count, 0);

            let c_fingerprint = unsafe {
                super::sequoia_import_result_get_content(import_result, 9999, &mut err_ptr)
            };
            assert!(c_fingerprint.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
            // err_ptr = ptr::null_mut();

            unsafe { sequoia_import_result_free(import_result) };
        });
    }

    #[test]
    fn sequoia_import_keys_invalid_public_key() {
        // Success is tested in primary_workflow().

        // Import failed.
        with_c_ephemeral_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let import_result = unsafe {
                super::sequoia_import_keys(
                    m,
                    INVALID_PUBLIC_KEY_BLOB.as_ptr(),
                    INVALID_PUBLIC_KEY_BLOB.len(),
                    &mut err_ptr,
                )
            };
            assert!(import_result.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
        });
    }

    // with_c_ephemeral_mechanism runs the provided function with a C-interface ephemeral mechanism,
    // as a convenience for tests of other aspects of the C bindings.
    fn with_c_ephemeral_mechanism(f: impl FnOnce(*mut SequoiaMechanism)) {
        let mut err_ptr: *mut SequoiaError = ptr::null_mut();

        let m = unsafe { sequoia_mechanism_new_ephemeral(&mut err_ptr) };
        assert!(!m.is_null());
        assert!(err_ptr.is_null());

        f(m);

        unsafe { sequoia_mechanism_free(m) };
    }
}
