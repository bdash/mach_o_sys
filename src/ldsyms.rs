/* automatically generated by rust-bindgen 0.70.1 */

#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
use crate::loader::*;

pub const _MH_EXECUTE_SYM: &[u8; 20] = b"__mh_execute_header\0";
pub const MH_EXECUTE_SYM: &[u8; 19] = b"_mh_execute_header\0";
pub const _MH_BUNDLE_SYM: &[u8; 19] = b"__mh_bundle_header\0";
pub const MH_BUNDLE_SYM: &[u8; 18] = b"_mh_bundle_header\0";
pub const _MH_DYLIB_SYM: &[u8; 18] = b"__mh_dylib_header\0";
pub const MH_DYLIB_SYM: &[u8; 17] = b"_mh_dylib_header\0";
pub const _MH_DYLINKER_SYM: &[u8; 21] = b"__mh_dylinker_header\0";
pub const MH_DYLINKER_SYM: &[u8; 20] = b"_mh_dylinker_header\0";
extern "C" {
    pub static _mh_execute_header: mach_header_64;
    pub static _mh_bundle_header: mach_header_64;
    pub static _mh_dylib_header: mach_header_64;
    pub static _mh_dylinker_header: mach_header_64;
}
