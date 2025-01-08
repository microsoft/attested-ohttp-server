// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod err;

use err::AttestError;
use libc::{c_char, c_int, size_t, c_void};
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

    fn ga_create(
        st: *mut *mut c_void
      ) -> c_int;
  
      fn ga_free(
        st: *mut c_void
      );
  
      fn ga_get_token(
        st: *mut c_void,
        app_data: *const u8,
        pcr: u32,
        jwt: *mut u8,
        jwt_len: *mut size_t,
        endpoint_url: *const c_char
      ) -> c_int;
  
      fn ga_decrypt(
        st: *mut c_void,
        cipher: *mut u8,
        len: *mut size_t
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
                Err(Box::new(AttestError::LibraryError(ret)))
            }
        },
        _e => Err(Box::new(AttestError::Convertion)),
    }
}

pub struct AttestationClient {
    st: *mut c_void
  }
  
  impl AttestationClient {
    pub fn new() -> Res<AttestationClient> {
      let mut c = AttestationClient { st: std::ptr::null_mut() };
      unsafe {
        let rc = ga_create(&mut c.st);
  
        if rc == 0 {
          return Ok(c);
        }
  
        return Err(Box::new(AttestError::Initialization));
      }
    }
  
    pub fn attest(&mut self, data: &[u8], pcrs: u32, endpoint_url: &str) -> Res<Vec<u8>> {
      match CString::new(endpoint_url) {
        Ok(endpoint_url_cstring) =>
          unsafe {
              let url_ptr = endpoint_url_cstring.as_ptr();
              let mut dstlen = 32 * 1024;
              let mut dst = Vec::with_capacity(dstlen);
              let pdst = dst.as_mut_ptr();
              let rc = ga_get_token(self.st, data.as_ptr(), pcrs, pdst, &mut dstlen, url_ptr);
  
              if rc == 0 {
                dst.set_len(dstlen);
                Ok(dst)
              } else {
                Err(Box::new(AttestError::LibraryError(rc)))
              }
          },
        _ => Err(Box::new(AttestError::Convertion)),
      }
    }
  
    pub fn decrypt(&mut self, data: &[u8]) -> Res<Vec<u8>> {
      unsafe {
        let mut buf = Vec::from(data);
        let mut len = data.len();
        let rc = ga_decrypt(self.st, buf.as_mut_ptr(), &mut len);
  
        if rc == 0 {
          buf.set_len(len);
          Ok(buf)
        } else {
          Err(Box::new(AttestError::LibraryError(rc)))
        }
      }
    }
  }
  
  impl Drop for AttestationClient {
    fn drop(&mut self) {
      unsafe {
        ga_free(self.st);
      }
    }
  }
  
  unsafe impl Send for AttestationClient {
  
  }