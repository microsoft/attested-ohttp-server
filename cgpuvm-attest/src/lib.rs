// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod err;

use err::AttestError;
use libc::{c_char, c_int, size_t};
use std::ffi::CString;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[link(name = "azguestattestation")]
extern "C" {
    fn get_attestation_token(
        app_data: *const u8,
        pcr_sel: u32,
        jwt: *mut u8,
        jwt_len: *mut size_t,
        endpoint_url: *const c_char,
    ) -> c_int;
}

pub fn attest(data: &[u8], pcrs: u32, endpoint_url: &str) -> Res<Vec<u8>> {
    match CString::new(endpoint_url) {
        Ok(endpoint_url_cstring) => unsafe {
            let mut dstlen = 32 * 1024;
            let mut dst = Vec::with_capacity(dstlen);
            let pdst = dst.as_mut_ptr();

            let url_ptr = endpoint_url_cstring.as_ptr();

            let ret = get_attestation_token(data.as_ptr(), pcrs, pdst, &mut dstlen, url_ptr);
            if ret == 0 {
                dst.set_len(dstlen);
                Ok(dst)
            } else {
                Err(Box::new(AttestError::MAAToken(ret)))
            }
        },
        _e => Err(Box::new(AttestError::Convertion)),
    }
}
