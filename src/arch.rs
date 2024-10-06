/* automatically generated by rust-bindgen 0.70.1 */

#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
extern crate libc;
use self::libc::{cpu_subtype_t, cpu_type_t};

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum NXByteOrder {
    NX_UnknownByteOrder = 0,
    NX_LittleEndian = 1,
    NX_BigEndian = 2,
}
#[repr(C)]
pub struct NXArchInfo {
    pub name: *const ::std::os::raw::c_char,
    pub cputype: cpu_type_t,
    pub cpusubtype: cpu_subtype_t,
    pub byteorder: NXByteOrder,
    pub description: *const ::std::os::raw::c_char,
}
impl Default for NXArchInfo {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fat_arch {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fat_arch_64 {
    _unused: [u8; 0],
}
extern "C" {
    pub fn NXGetAllArchInfos() -> *const NXArchInfo;
    pub fn NXGetLocalArchInfo() -> *const NXArchInfo;
    pub fn NXGetArchInfoFromName(name: *const ::std::os::raw::c_char) -> *const NXArchInfo;
    pub fn NXGetArchInfoFromCpuType(
        cputype: cpu_type_t,
        cpusubtype: cpu_subtype_t,
    ) -> *const NXArchInfo;
    pub fn NXFreeArchInfo(x: *const NXArchInfo);
    pub fn NXFindBestFatArch(
        cputype: cpu_type_t,
        cpusubtype: cpu_subtype_t,
        fat_archs: *mut fat_arch,
        nfat_archs: u32,
    ) -> *mut fat_arch;
    pub fn NXFindBestFatArch_64(
        cputype: cpu_type_t,
        cpusubtype: cpu_subtype_t,
        fat_archs64: *mut fat_arch_64,
        nfat_archs: u32,
    ) -> *mut fat_arch_64;
    pub fn NXCombineCpuSubtypes(
        cputype: cpu_type_t,
        cpusubtype1: cpu_subtype_t,
        cpusubtype2: cpu_subtype_t,
    ) -> cpu_subtype_t;
}
