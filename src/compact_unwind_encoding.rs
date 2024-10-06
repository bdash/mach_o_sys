/* automatically generated by rust-bindgen 0.70.1 */

#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]

pub const UNWIND_SECTION_VERSION: u32 = 1;
pub const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
pub const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
pub type compact_unwind_encoding_t = u32;
pub const UNWIND_IS_NOT_FUNCTION_START: _bindgen_ty_1 = _bindgen_ty_1::UNWIND_IS_NOT_FUNCTION_START;
pub const UNWIND_HAS_LSDA: _bindgen_ty_1 = _bindgen_ty_1::UNWIND_HAS_LSDA;
pub const UNWIND_PERSONALITY_MASK: _bindgen_ty_1 = _bindgen_ty_1::UNWIND_PERSONALITY_MASK;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_1 {
    UNWIND_IS_NOT_FUNCTION_START = 2147483648,
    UNWIND_HAS_LSDA = 1073741824,
    UNWIND_PERSONALITY_MASK = 805306368,
}
pub const UNWIND_X86_MODE_MASK: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_MODE_MASK;
pub const UNWIND_X86_MODE_EBP_FRAME: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_MODE_EBP_FRAME;
pub const UNWIND_X86_MODE_STACK_IMMD: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_MODE_STACK_IMMD;
pub const UNWIND_X86_MODE_STACK_IND: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_MODE_STACK_IND;
pub const UNWIND_X86_MODE_DWARF: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_MODE_DWARF;
pub const UNWIND_X86_EBP_FRAME_REGISTERS: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_EBP_FRAME_REGISTERS;
pub const UNWIND_X86_EBP_FRAME_OFFSET: _bindgen_ty_2 = _bindgen_ty_2::UNWIND_X86_EBP_FRAME_OFFSET;
pub const UNWIND_X86_FRAMELESS_STACK_SIZE: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_EBP_FRAME_OFFSET;
pub const UNWIND_X86_FRAMELESS_STACK_ADJUST: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_FRAMELESS_STACK_ADJUST;
pub const UNWIND_X86_FRAMELESS_STACK_REG_COUNT: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_FRAMELESS_STACK_REG_COUNT;
pub const UNWIND_X86_FRAMELESS_STACK_REG_PERMUTATION: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_FRAMELESS_STACK_REG_PERMUTATION;
pub const UNWIND_X86_DWARF_SECTION_OFFSET: _bindgen_ty_2 =
    _bindgen_ty_2::UNWIND_X86_DWARF_SECTION_OFFSET;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_2 {
    UNWIND_X86_MODE_MASK = 251658240,
    UNWIND_X86_MODE_EBP_FRAME = 16777216,
    UNWIND_X86_MODE_STACK_IMMD = 33554432,
    UNWIND_X86_MODE_STACK_IND = 50331648,
    UNWIND_X86_MODE_DWARF = 67108864,
    UNWIND_X86_EBP_FRAME_REGISTERS = 32767,
    UNWIND_X86_EBP_FRAME_OFFSET = 16711680,
    UNWIND_X86_FRAMELESS_STACK_ADJUST = 57344,
    UNWIND_X86_FRAMELESS_STACK_REG_COUNT = 7168,
    UNWIND_X86_FRAMELESS_STACK_REG_PERMUTATION = 1023,
    UNWIND_X86_DWARF_SECTION_OFFSET = 16777215,
}
pub const UNWIND_X86_REG_NONE: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_NONE;
pub const UNWIND_X86_REG_EBX: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_EBX;
pub const UNWIND_X86_REG_ECX: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_ECX;
pub const UNWIND_X86_REG_EDX: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_EDX;
pub const UNWIND_X86_REG_EDI: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_EDI;
pub const UNWIND_X86_REG_ESI: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_ESI;
pub const UNWIND_X86_REG_EBP: _bindgen_ty_3 = _bindgen_ty_3::UNWIND_X86_REG_EBP;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_3 {
    UNWIND_X86_REG_NONE = 0,
    UNWIND_X86_REG_EBX = 1,
    UNWIND_X86_REG_ECX = 2,
    UNWIND_X86_REG_EDX = 3,
    UNWIND_X86_REG_EDI = 4,
    UNWIND_X86_REG_ESI = 5,
    UNWIND_X86_REG_EBP = 6,
}
pub const UNWIND_X86_64_MODE_MASK: _bindgen_ty_4 = _bindgen_ty_4::UNWIND_X86_64_MODE_MASK;
pub const UNWIND_X86_64_MODE_RBP_FRAME: _bindgen_ty_4 = _bindgen_ty_4::UNWIND_X86_64_MODE_RBP_FRAME;
pub const UNWIND_X86_64_MODE_STACK_IMMD: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_MODE_STACK_IMMD;
pub const UNWIND_X86_64_MODE_STACK_IND: _bindgen_ty_4 = _bindgen_ty_4::UNWIND_X86_64_MODE_STACK_IND;
pub const UNWIND_X86_64_MODE_DWARF: _bindgen_ty_4 = _bindgen_ty_4::UNWIND_X86_64_MODE_DWARF;
pub const UNWIND_X86_64_RBP_FRAME_REGISTERS: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_RBP_FRAME_REGISTERS;
pub const UNWIND_X86_64_RBP_FRAME_OFFSET: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_RBP_FRAME_OFFSET;
pub const UNWIND_X86_64_FRAMELESS_STACK_SIZE: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_RBP_FRAME_OFFSET;
pub const UNWIND_X86_64_FRAMELESS_STACK_ADJUST: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_FRAMELESS_STACK_ADJUST;
pub const UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT;
pub const UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION;
pub const UNWIND_X86_64_DWARF_SECTION_OFFSET: _bindgen_ty_4 =
    _bindgen_ty_4::UNWIND_X86_64_DWARF_SECTION_OFFSET;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_4 {
    UNWIND_X86_64_MODE_MASK = 251658240,
    UNWIND_X86_64_MODE_RBP_FRAME = 16777216,
    UNWIND_X86_64_MODE_STACK_IMMD = 33554432,
    UNWIND_X86_64_MODE_STACK_IND = 50331648,
    UNWIND_X86_64_MODE_DWARF = 67108864,
    UNWIND_X86_64_RBP_FRAME_REGISTERS = 32767,
    UNWIND_X86_64_RBP_FRAME_OFFSET = 16711680,
    UNWIND_X86_64_FRAMELESS_STACK_ADJUST = 57344,
    UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT = 7168,
    UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION = 1023,
    UNWIND_X86_64_DWARF_SECTION_OFFSET = 16777215,
}
pub const UNWIND_X86_64_REG_NONE: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_NONE;
pub const UNWIND_X86_64_REG_RBX: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_RBX;
pub const UNWIND_X86_64_REG_R12: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_R12;
pub const UNWIND_X86_64_REG_R13: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_R13;
pub const UNWIND_X86_64_REG_R14: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_R14;
pub const UNWIND_X86_64_REG_R15: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_R15;
pub const UNWIND_X86_64_REG_RBP: _bindgen_ty_5 = _bindgen_ty_5::UNWIND_X86_64_REG_RBP;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_5 {
    UNWIND_X86_64_REG_NONE = 0,
    UNWIND_X86_64_REG_RBX = 1,
    UNWIND_X86_64_REG_R12 = 2,
    UNWIND_X86_64_REG_R13 = 3,
    UNWIND_X86_64_REG_R14 = 4,
    UNWIND_X86_64_REG_R15 = 5,
    UNWIND_X86_64_REG_RBP = 6,
}
pub const UNWIND_ARM64_MODE_MASK: _bindgen_ty_6 = _bindgen_ty_6::UNWIND_ARM64_MODE_MASK;
pub const UNWIND_ARM64_MODE_FRAMELESS: _bindgen_ty_6 = _bindgen_ty_6::UNWIND_ARM64_MODE_FRAMELESS;
pub const UNWIND_ARM64_MODE_DWARF: _bindgen_ty_6 = _bindgen_ty_6::UNWIND_ARM64_MODE_DWARF;
pub const UNWIND_ARM64_MODE_FRAME: _bindgen_ty_6 = _bindgen_ty_6::UNWIND_ARM64_MODE_FRAME;
pub const UNWIND_ARM64_FRAME_X19_X20_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_X19_X20_PAIR;
pub const UNWIND_ARM64_FRAME_X21_X22_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_X21_X22_PAIR;
pub const UNWIND_ARM64_FRAME_X23_X24_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_X23_X24_PAIR;
pub const UNWIND_ARM64_FRAME_X25_X26_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_X25_X26_PAIR;
pub const UNWIND_ARM64_FRAME_X27_X28_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_X27_X28_PAIR;
pub const UNWIND_ARM64_FRAME_D8_D9_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_D8_D9_PAIR;
pub const UNWIND_ARM64_FRAME_D10_D11_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_D10_D11_PAIR;
pub const UNWIND_ARM64_FRAME_D12_D13_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_D12_D13_PAIR;
pub const UNWIND_ARM64_FRAME_D14_D15_PAIR: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAME_D14_D15_PAIR;
pub const UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK;
pub const UNWIND_ARM64_DWARF_SECTION_OFFSET: _bindgen_ty_6 =
    _bindgen_ty_6::UNWIND_ARM64_DWARF_SECTION_OFFSET;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_6 {
    UNWIND_ARM64_MODE_MASK = 251658240,
    UNWIND_ARM64_MODE_FRAMELESS = 33554432,
    UNWIND_ARM64_MODE_DWARF = 50331648,
    UNWIND_ARM64_MODE_FRAME = 67108864,
    UNWIND_ARM64_FRAME_X19_X20_PAIR = 1,
    UNWIND_ARM64_FRAME_X21_X22_PAIR = 2,
    UNWIND_ARM64_FRAME_X23_X24_PAIR = 4,
    UNWIND_ARM64_FRAME_X25_X26_PAIR = 8,
    UNWIND_ARM64_FRAME_X27_X28_PAIR = 16,
    UNWIND_ARM64_FRAME_D8_D9_PAIR = 256,
    UNWIND_ARM64_FRAME_D10_D11_PAIR = 512,
    UNWIND_ARM64_FRAME_D12_D13_PAIR = 1024,
    UNWIND_ARM64_FRAME_D14_D15_PAIR = 2048,
    UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK = 16773120,
    UNWIND_ARM64_DWARF_SECTION_OFFSET = 16777215,
}
pub const UNWIND_ARM_MODE_MASK: _bindgen_ty_7 = _bindgen_ty_7::UNWIND_ARM_MODE_MASK;
pub const UNWIND_ARM_MODE_FRAME: _bindgen_ty_7 = _bindgen_ty_7::UNWIND_ARM_MODE_FRAME;
pub const UNWIND_ARM_MODE_FRAME_D: _bindgen_ty_7 = _bindgen_ty_7::UNWIND_ARM_MODE_FRAME_D;
pub const UNWIND_ARM_MODE_DWARF: _bindgen_ty_7 = _bindgen_ty_7::UNWIND_ARM_MODE_DWARF;
pub const UNWIND_ARM_FRAME_STACK_ADJUST_MASK: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_STACK_ADJUST_MASK;
pub const UNWIND_ARM_FRAME_FIRST_PUSH_R4: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_FIRST_PUSH_R4;
pub const UNWIND_ARM_FRAME_FIRST_PUSH_R5: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_FIRST_PUSH_R5;
pub const UNWIND_ARM_FRAME_FIRST_PUSH_R6: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_FIRST_PUSH_R6;
pub const UNWIND_ARM_FRAME_SECOND_PUSH_R8: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_SECOND_PUSH_R8;
pub const UNWIND_ARM_FRAME_SECOND_PUSH_R9: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_SECOND_PUSH_R9;
pub const UNWIND_ARM_FRAME_SECOND_PUSH_R10: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_SECOND_PUSH_R10;
pub const UNWIND_ARM_FRAME_SECOND_PUSH_R11: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_SECOND_PUSH_R11;
pub const UNWIND_ARM_FRAME_SECOND_PUSH_R12: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_SECOND_PUSH_R12;
pub const UNWIND_ARM_FRAME_D_REG_COUNT_MASK: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_FRAME_D_REG_COUNT_MASK;
pub const UNWIND_ARM_DWARF_SECTION_OFFSET: _bindgen_ty_7 =
    _bindgen_ty_7::UNWIND_ARM_DWARF_SECTION_OFFSET;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum _bindgen_ty_7 {
    UNWIND_ARM_MODE_MASK = 251658240,
    UNWIND_ARM_MODE_FRAME = 16777216,
    UNWIND_ARM_MODE_FRAME_D = 33554432,
    UNWIND_ARM_MODE_DWARF = 67108864,
    UNWIND_ARM_FRAME_STACK_ADJUST_MASK = 12582912,
    UNWIND_ARM_FRAME_FIRST_PUSH_R4 = 1,
    UNWIND_ARM_FRAME_FIRST_PUSH_R5 = 2,
    UNWIND_ARM_FRAME_FIRST_PUSH_R6 = 4,
    UNWIND_ARM_FRAME_SECOND_PUSH_R8 = 8,
    UNWIND_ARM_FRAME_SECOND_PUSH_R9 = 16,
    UNWIND_ARM_FRAME_SECOND_PUSH_R10 = 32,
    UNWIND_ARM_FRAME_SECOND_PUSH_R11 = 64,
    UNWIND_ARM_FRAME_SECOND_PUSH_R12 = 128,
    UNWIND_ARM_FRAME_D_REG_COUNT_MASK = 1792,
    UNWIND_ARM_DWARF_SECTION_OFFSET = 16777215,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_section_header {
    pub version: u32,
    pub commonEncodingsArraySectionOffset: u32,
    pub commonEncodingsArrayCount: u32,
    pub personalityArraySectionOffset: u32,
    pub personalityArrayCount: u32,
    pub indexSectionOffset: u32,
    pub indexCount: u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_section_header_index_entry {
    pub functionOffset: u32,
    pub secondLevelPagesSectionOffset: u32,
    pub lsdaIndexArraySectionOffset: u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_section_header_lsda_index_entry {
    pub functionOffset: u32,
    pub lsdaOffset: u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_regular_second_level_entry {
    pub functionOffset: u32,
    pub encoding: compact_unwind_encoding_t,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_regular_second_level_page_header {
    pub kind: u32,
    pub entryPageOffset: u16,
    pub entryCount: u16,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct unwind_info_compressed_second_level_page_header {
    pub kind: u32,
    pub entryPageOffset: u16,
    pub entryCount: u16,
    pub encodingsPageOffset: u16,
    pub encodingsCount: u16,
}
