// SPDX-License-Identifier: LGPL-2.0-or-later

use anyhow::Context as _;
use libc::{c_char, size_t};
use openpgp::cert::prelude::*;
use openpgp::parse::{stream::*, PacketParser, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer};
use openpgp::KeyHandle;
use sequoia_cert_store::{Store as _, StoreUpdate as _};
use sequoia_keystore;
use sequoia_openpgp as openpgp;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::Arc;

use crate::{set_error_from, OpenpgpError};

pub struct OpenpgpMechanism<'a> {
    keystore: sequoia_keystore::Keystore,
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
}

impl<'a> OpenpgpMechanism<'a> {
    fn from_directory(dir: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let home_dir = if dir.as_ref() == Path::new("") {
            let data_dir = dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("unable to determine XDG data directory"))?;
            data_dir.join("sequoia")
        } else {
            dir.as_ref().to_path_buf()
        };

        let keystore_dir = home_dir.join("data").join("keystore");
        let context = sequoia_keystore::Context::configure()
            .home(&keystore_dir)
            .build()?;
        let keystore = sequoia_keystore::Keystore::connect(&context)?;

        let certstore_dir = home_dir.join("data").join("pgp.cert.d");
        fs::create_dir_all(&certstore_dir)?;
        let certstore = sequoia_cert_store::CertStore::open(&certstore_dir)?;
        Ok(Self {
            keystore,
            certstore: Arc::new(certstore),
        })
    }

    fn ephemeral(keyring: &[u8]) -> Result<Self, anyhow::Error> {
        let ppr = PacketParser::from_bytes(keyring)?;
        let certs: Vec<openpgp::Cert> =
            CertParser::from(ppr).collect::<openpgp::Result<Vec<_>>>()?;
        let context = sequoia_keystore::Context::configure().ephemeral().build()?;
        let certstore = Arc::new(sequoia_cert_store::CertStore::empty());
        for cert in certs {
            certstore.update(Arc::new(sequoia_cert_store::LazyCert::from(cert)))?
        }
        Ok(Self {
            keystore: sequoia_keystore::Keystore::connect(&context)?,
            certstore,
        })
    }

    fn sign(
        &mut self,
        key_handle: &str,
        password: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let primary_key_handle: KeyHandle = key_handle.parse()?;
        let certs = self
            .certstore
            .lookup_by_cert_or_subkey(&primary_key_handle)
            .with_context(|| format!("Failed to load {} from certificate store", key_handle))?
            .into_iter()
            .filter_map(|cert| match cert.to_cert() {
                Ok(cert) => Some(cert.clone()),
                Err(_) => None,
            })
            .collect::<Vec<Cert>>();

        let p = &StandardPolicy::new();

        let mut signing_key_handles: Vec<KeyHandle> = vec![];
        for cert in certs {
            for ka in cert.keys().with_policy(p, None).for_signing() {
                signing_key_handles.push(ka.key().fingerprint().into());
            }
        }

        if signing_key_handles.len() == 0 {
            return Err(anyhow::anyhow!(
                "No matching signing key for {}",
                key_handle
            ));
        }

        let mut keys = self.keystore.find_key(signing_key_handles[0].clone())?;

        if keys.len() == 0 {
            return Err(anyhow::anyhow!("No matching key in keystore"));
        }
        if let Some(password) = password {
            keys[0].unlock(password.into())?;
        }

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Signer::new(message, &mut keys[0]).build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(data)?;
            message.finalize()?;
        }
        Ok(sink)
    }

    fn verify(&mut self, signature: &[u8]) -> Result<OpenpgpVerificationResult, anyhow::Error> {
        let p = &StandardPolicy::new();
        let h = Helper {
            certstore: self.certstore.clone(),
            signer: Default::default(),
        };
        let mut v = VerifierBuilder::from_bytes(signature)?.with_policy(p, None, h)?;
        let mut content = Vec::new();
        v.read_to_end(&mut content)?;

        assert!(v.message_processed());

        match &v.helper_ref().signer {
            Some(signer) => Ok(OpenpgpVerificationResult {
                content,
                signer: CString::new(signer.fingerprint().to_hex().as_bytes()).unwrap(),
            }),
            None => Err(anyhow::anyhow!("No valid signature")),
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
        for (_, layer) in structure.into_iter().enumerate() {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    let result = results.iter().find(|r| r.is_ok());
                    if let Some(result) = result {
                        self.signer = Some(result.as_ref().unwrap().ka.cert().cert().to_owned());
                        return Ok(());
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }
        Err(anyhow::anyhow!("No valid signature"))
    }
}

pub struct OpenpgpSignature {
    data: Vec<u8>,
}

pub struct OpenpgpVerificationResult {
    content: Vec<u8>,
    signer: CString,
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_mechanism_new_from_directory<'a>(
    dir_ptr: *const c_char,
    err_ptr: *mut *mut OpenpgpError,
) -> *mut OpenpgpMechanism<'a> {
    let c_dir = CStr::from_ptr(dir_ptr);
    let os_dir = OsStr::from_bytes(c_dir.to_bytes());
    match OpenpgpMechanism::from_directory(os_dir) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_mechanism_new_ephemeral<'a>(
    keyring_ptr: *const u8,
    keyring_len: size_t,
    err_ptr: *mut *mut OpenpgpError,
) -> *mut OpenpgpMechanism<'a> {
    let keyring = slice::from_raw_parts(keyring_ptr, keyring_len);
    match OpenpgpMechanism::ephemeral(keyring) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_mechanism_free(mechanism_ptr: *mut OpenpgpMechanism) {
    drop(Box::from_raw(mechanism_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_signature_free(signature_ptr: *mut OpenpgpSignature) {
    drop(Box::from_raw(signature_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_signature_get_data(
    signature_ptr: *const OpenpgpSignature,
    data_len: *mut size_t,
) -> *const u8 {
    *data_len = (*signature_ptr).data.len();
    (*signature_ptr).data.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_verification_result_free(
    result_ptr: *mut OpenpgpVerificationResult,
) {
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_verification_result_get_content(
    result_ptr: *const OpenpgpVerificationResult,
    data_len: *mut size_t,
) -> *const u8 {
    *data_len = (*result_ptr).content.len();
    (*result_ptr).content.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_verification_result_get_signer(
    result_ptr: *const OpenpgpVerificationResult,
) -> *const c_char {
    (*result_ptr).signer.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_sign(
    mechanism_ptr: *mut OpenpgpMechanism,
    key_handle_ptr: *const c_char,
    password_ptr: *const c_char,
    data_ptr: *const u8,
    data_len: size_t,
    err_ptr: *mut *mut OpenpgpError,
) -> *mut OpenpgpSignature {
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
            Ok(key_handle) => Some(key_handle),
            Err(e) => {
                set_error_from(err_ptr, e.into());
                return ptr::null_mut();
            }
        }
    };

    let data = slice::from_raw_parts(data_ptr, data_len);
    match (&mut *mechanism_ptr).sign(key_handle, password, &data) {
        Ok(signature) => return Box::into_raw(Box::new(OpenpgpSignature { data: signature })),
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn openpgp_verify(
    mechanism_ptr: *mut OpenpgpMechanism,
    signature_ptr: *const u8,
    signature_len: size_t,
    err_ptr: *mut *mut OpenpgpError,
) -> *mut OpenpgpVerificationResult {
    assert!(!mechanism_ptr.is_null());
    assert!(!signature_ptr.is_null());

    let signature = slice::from_raw_parts(signature_ptr, signature_len);
    match (&mut *mechanism_ptr).verify(&signature) {
        Ok(result) => return Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    }
}
