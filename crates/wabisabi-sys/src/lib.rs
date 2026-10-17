//! Raw bindings to `libwabisabi` (vendor/libwabisabi/include/wabisabi_ffi.h, ownership_ffi.h).
//! The library is stateless: every call takes and returns serialized byte blobs.
#![allow(non_camel_case_types)]

use std::os::raw::c_int;

pub const SCALAR_SIZE: usize = 32;
pub const GE_SIZE: usize = 33;
pub const VALUE_SIZE: usize = 8;
pub const RAND_SIZE: usize = SCALAR_SIZE;
pub const SK_SIZE: usize = 5 * SCALAR_SIZE;
pub const IPARAMS_SIZE: usize = 2 * GE_SIZE;
pub const MAC_SIZE: usize = SCALAR_SIZE + GE_SIZE;
pub const PRESENTATION_SIZE: usize = 5 * GE_SIZE;
pub const CREDENTIAL_SIZE: usize = VALUE_SIZE + SCALAR_SIZE + MAC_SIZE;
pub const CREDENTIAL_COUNT: usize = 2;
pub const VALIDATION_SIZE: usize = 353;
pub const ISSUER_MSTATE_MAX_SIZE: usize = 8;
pub const MAX_REQUEST_SIZE: usize = 64 * 1024;

pub type wabisabi_error_t = c_int;
pub const WABISABI_OK: wabisabi_error_t = 0;

/// `wabisabi_spk_type_t`
pub const WABISABI_SPK_P2WPKH: c_int = 0;
pub const WABISABI_SPK_P2TR: c_int = 1;

extern "C" {
    pub fn wabisabi_init();
    pub fn wabisabi_cleanup();
    pub fn wabisabi_iparams_from_sk(sk_bytes: *const u8, out_bytes: *mut u8) -> wabisabi_error_t;

    pub fn wabisabi_issuer_handle_zero(
        sk_bytes: *const u8,
        max_amount: i64,
        mstate_in: *const u8,
        mstate_in_len: c_int,
        req_bytes: *const u8,
        req_len: c_int,
        rand_bytes: *const u8,
        resp_out: *mut u8,
        resp_out_cap: c_int,
        resp_len_out: *mut c_int,
        mstate_out: *mut u8,
        mstate_out_cap: c_int,
        mstate_out_len: *mut c_int,
    ) -> wabisabi_error_t;

    pub fn wabisabi_issuer_handle_real(
        sk_bytes: *const u8,
        max_amount: i64,
        mstate_in: *const u8,
        mstate_in_len: c_int,
        req_bytes: *const u8,
        req_len: c_int,
        rand_bytes: *const u8,
        resp_out: *mut u8,
        resp_out_cap: c_int,
        resp_len_out: *mut c_int,
        mstate_out: *mut u8,
        mstate_out_cap: c_int,
        mstate_out_len: *mut c_int,
    ) -> wabisabi_error_t;

    pub fn wabisabi_client_create_zero_request(
        rand_bytes: *const u8,
        req_out: *mut u8,
        req_out_cap: c_int,
        req_len_out: *mut c_int,
        val_out: *mut u8,
    ) -> wabisabi_error_t;

    pub fn wabisabi_client_create_real_request(
        iparams_bytes: *const u8,
        max_amount: i64,
        amounts: *const i64,
        n_amounts: c_int,
        creds_bytes: *const u8,
        n_creds: c_int,
        rand_bytes: *const u8,
        req_out: *mut u8,
        req_out_cap: c_int,
        req_len_out: *mut c_int,
        val_out: *mut u8,
    ) -> wabisabi_error_t;

    /// sabid patch (vendor/libwabisabi/PATCHES.md): presentation-only request.
    pub fn wabisabi_client_create_present_request(
        iparams_bytes: *const u8,
        max_amount: i64,
        creds_bytes: *const u8,
        n_creds: c_int,
        rand_bytes: *const u8,
        req_out: *mut u8,
        req_out_cap: c_int,
        req_len_out: *mut c_int,
        val_out: *mut u8,
    ) -> wabisabi_error_t;

    pub fn wabisabi_client_handle_response(
        iparams_bytes: *const u8,
        resp_bytes: *const u8,
        resp_len: c_int,
        val_bytes: *const u8,
        creds_out: *mut u8,
        creds_out_cap: c_int,
        n_creds_out: *mut c_int,
    ) -> wabisabi_error_t;
}
