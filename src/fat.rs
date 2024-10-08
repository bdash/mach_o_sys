/* automatically generated by rust-bindgen 0.70.1 */

#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]

pub const FAT_MAGIC: u32 = 3405691582;
pub const FAT_CIGAM: u32 = 3199925962;
pub const FAT_MAGIC_64: u32 = 3405691583;
pub const FAT_CIGAM_64: u32 = 3216703178;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct fat_header {
    pub magic: u32,
    pub nfat_arch: u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct fat_arch {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct fat_arch_64 {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
}
