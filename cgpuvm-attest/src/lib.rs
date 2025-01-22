// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod err;

use err::AttestError;
use libc::{c_char, c_int, c_void, size_t};
use std::ffi::CString;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[link(name = "azguestattestation")]
extern "C" {
    fn ga_create(ppAttestationClient: *mut *mut c_void) -> c_int;

    fn ga_free(pAttestationClient: *mut c_void);

    fn ga_get_token(
        pAttestationClient: *mut c_void,
        app_data: *const u8,
        pcr: u32,
        jwt: *mut u8,
        jwt_len: *mut size_t,
        endpoint_url: *const c_char,
    ) -> c_int;

    fn ga_decrypt(pAttestationClient: *mut c_void, cipher: *mut u8, len: *mut size_t) -> c_int;
}

pub struct AttestationClient {
    p_attestation_client: *mut c_void,
}

impl AttestationClient {
    pub fn new() -> Res<AttestationClient> {
        let mut manager = AttestationClient {
            p_attestation_client: std::ptr::null_mut(),
        };

        unsafe {
            let rc = ga_create(&mut manager.p_attestation_client);
            if rc == 0 {
                return Ok(manager);
            }

            Err(Box::new(AttestError::Initialization))
        }
    }

    pub fn attest(&mut self, data: &[u8], pcrs: u32, endpoint_url: &str) -> Res<Vec<u8>> {
        match CString::new(endpoint_url) {
            Ok(endpoint_url_cstring) => unsafe {
                let mut dstlen = 32 * 1024;
                let mut dst = Vec::with_capacity(dstlen);
                let pdst = dst.as_mut_ptr();

                let url_ptr = endpoint_url_cstring.as_ptr();

                let rc = ga_get_token(
                    self.p_attestation_client,
                    data.as_ptr(),
                    pcrs,
                    pdst,
                    &mut dstlen,
                    url_ptr,
                );

                if rc == 0 {
                    dst.set_len(dstlen);
                    return Ok(dst);
                }

                Err(Box::new(AttestError::LibraryError(rc)))
            },
            _ => Err(Box::new(AttestError::Convertion)),
        }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Res<Vec<u8>> {
        unsafe {
            let mut buf = Vec::from(data);
            let mut len = data.len();
            let rc = ga_decrypt(self.p_attestation_client, buf.as_mut_ptr(), &mut len);

            if rc == 0 {
                buf.set_len(len);
                return Ok(buf);
            }

            Err(Box::new(AttestError::LibraryError(rc)))
        }
    }
}

impl Drop for AttestationClient {
    fn drop(&mut self) {
        unsafe {
            ga_free(self.p_attestation_client);
        }
    }
}

unsafe impl Send for AttestationClient {}
