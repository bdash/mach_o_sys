/* automatically generated by rust-bindgen 0.70.1 */

#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
extern crate libc;
use self::libc::{cpu_subtype_t, cpu_type_t};
use crate::loader::*;

extern "C" {
    #[doc = " @function macho_cpu_type_for_arch_name\n\n @abstract\n      Converts an architecture name into a cpu type/subtype pair.\n\n @param archName\n      An architecture name (e.g \"arm64e\" or \"x86_64\").\n\n @param type\n      A pointer to where to store the cpu type of the given name.\n\n @param subtype\n      A pointer to where to store the cpu subtype of the given name.\n\n @return\n\t\tIf the archName is known, returns true and fills in the type/subtype.\n\t\tIf the archName is unknown, returns false."]
    pub fn macho_cpu_type_for_arch_name(
        archName: *const ::std::os::raw::c_char,
        type_: *mut cpu_type_t,
        subtype: *mut cpu_subtype_t,
    ) -> bool;
    #[doc = " @function macho_arch_name_for_cpu_type\n\n @abstract\n      Converts a cpu type/subtype pair into the architecture name.\n\n @param type\n      The cpu type from <machine/machine.h> (e.g CPU_TYPE_ARM64)\n\n @param subtype\n      The cpu subtype from <machine/machine.h> (e.g CPU_SUBTYPE_ARM64E)\n\n @return\n\t\tReturns a static c-string which is the name for the cpu type/subtype (e.g. \"arm64e\").\n\t\tIf the cpu type/subtype is unknown, NULL will be returned.\n\t\tThe string returned is static and does not need to be deallocated."]
    pub fn macho_arch_name_for_cpu_type(
        type_: cpu_type_t,
        subtype: cpu_subtype_t,
    ) -> *const ::std::os::raw::c_char;
    #[doc = " @function macho_arch_name_for_mach_header\n\n @abstract\n      Returns the architecture name from the cpu type/subtype in a mach_header.\n      This is a convenience wrapper around macho_arch_name_for_cpu_type().\n\n @param mh\n      A pointer to the header of a mach-o file.\n      If NULL is passed, the architecture name of the main executable will be returned.\n\n @return\n\t\tReturns a static c-string which is the name for architecture of the mach-o file (e.g. \"arm64e\").\n\t\tIf the architecture is unknown, NULL will be returned.\n\t\tThe string returned is static and does not need to be deallocated."]
    pub fn macho_arch_name_for_mach_header(mh: *const mach_header)
        -> *const ::std::os::raw::c_char;
    #[doc = " @function macho_for_each_slice\n\n @abstract\n      Temporarily maps a mach-o or universal file and iterates the slices.\n      If the file is mach-o, the block is called once with the mach-o file mapped.\n      If the file is universal (aka fat), the block is called once per slice in the order in the header.\n      If the path does not exist or does, but is not a mach-o file, the block is never called.\n\n @param path\n      The path to the file to inspect.\n\n @param callback\n      A block to call once per slice.\n      Can be NULL.  In which case the return value tells you if the file is mach-o or fat.\n      The slice pointer is only valid during the block invocation.\n      To stop iterating the slices, set *stop to true.\n\n @return\n      Returns zero on success, otherwise it returns an errno value.\n      Common returned errors:\n          ENOENT  - path does not exist\n          EACCES - path exists put caller does not have permission to access it\n          EFTYPE - path exists but it is not a mach-o or fat file\n          EBADMACHO - path is a mach-o file, but it is malformed"]
    pub fn macho_for_each_slice(
        path: *const ::std::os::raw::c_char,
        callback: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
    #[doc = " @function macho_for_each_slice_in_fd\n\n @abstract\n      Temporarily maps a mach-o or universal file and iterates the slices.\n      If the fd is to a mach-o, the block is called once with the mach-o file mapped.\n      If the fd is to a universal (aka fat), the block is called once per slice in the order in the header.\n      If the fd is closed or not mmap()able, the block is never called.\n\n @param fd\n      An open file descriptor to a mmap()able file.\n\n @param callback\n      A block to call once per slice.\n      Can be NULL.  In which case the return value tells you if the file is mach-o or fat.\n      The slice pointer is only valid during the block invocation.\n      To stop iterating the slices, set *stop to true.\n\n @return\n      Returns zero on success, otherwise it returns an errno value.\n      Common returned errors:\n          EFTYPE - fd content is not a mach-o or fat file\n          EBADMACHO - fd content is a mach-o file, but it is malformed"]
    pub fn macho_for_each_slice_in_fd(
        fd: ::std::os::raw::c_int,
        callback: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
    #[doc = " @function macho_best_slice\n\n @abstract\n      Examines a mach-o or universal file to find the slice that would be loaded.  That is, for dylib/bundles, which\n      slice dyld would load.  For main executables, which slice the kernel would use.\n      In simulator processes, only other simulator main executables will be considered loadable.\n      If the file is mach-o and is the right arch and platform to load, the block is called once with the mach-o file mapped.\n      If the file is universal (aka fat) file, the best slice is found and the block is called once with the mapped slice.\n      If the file is universal (aka fat) file, but none of the slices are loadable, the callback is not called, and EBADARCH is returned.\n      If the path does not exist or does but is not a mach-o or universal file, the block is never called, and an error is returned.\n\n @param path\n      The path to the file to inspect.\n\n @param callback\n      A block to call once with the best slice.\n      Can be NULL.  In which case the return value tells you if there was a loadable slice\n      The slice pointer is only valid during the block invocation.\n\n @return\n      Returns zero on success (meaning there is a best slice), otherwise it returns an errno value.\n      Common returned errors:\n          ENOENT  - path does not exist\n          EACCES - path exists put caller does not have permission to access it\n          EFTYPE - path exists but it is not a mach-o or fat file\n          EBADARCH - path exists and is mach-o or fat, but none of the slices are loadable\n          EBADMACHO - path is a mach-o file, but it is malformed"]
    pub fn macho_best_slice(
        path: *const ::std::os::raw::c_char,
        bestSlice: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
    #[doc = " @function macho_best_slice_in_fd\n\n @abstract\n      Examines a mach-o or universal file to find the slice that would be loaded.  That is, for dylib/bundles, which\n      slice dyld would load.  For main executables, which slice the kernel would use.\n      In simulator processes, only other simulator main executables will be considered loadable.\n      If the fd is to a mach-o and is the right arch and platform to load, the block is call once with the mach-o file mapped.\n      If the fd is to a universal (aka fat) file, the best slice is found and the block is called once with the mapped slice.\n      If the fd is closed or not mmap()able, the block is never called.\n\n @param fd\n      An open file descriptor to a mmap()able file.\n\n @param callback\n      A block to call once with the best slice.\n      Can be NULL.  In which case the return value tells you if there was a loadable slice\n      The slice pointer is only valid during the block invocation.\n\n @return\n      Returns zero on success (meaning there is a best slice), otherwise it returns an errno value.\n      Common returned errors:\n          EFTYPE - fd content is not a mach-o or fat file\n          EBADMACHO - fd content is a mach-o file, but it is malformed\n          EBADARCH - fd content is a mach-o or fat, but none of the slices are loadable"]
    pub fn macho_best_slice_in_fd(
        fd: ::std::os::raw::c_int,
        bestSlice: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
