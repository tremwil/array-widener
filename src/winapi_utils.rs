use std::ops::Range;

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HMODULE,
        System::{
            LibraryLoader::{
                GetModuleHandleExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            Threading::GetCurrentProcess,
        },
    },
};

/// Get an HMODULE given a pointer to memory inside of it.
pub fn hmodule_from_ptr(ptr: *const ()) -> Option<HMODULE> {
    let mut hmod = HMODULE::default();
    unsafe {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCSTR(ptr as *const _),
            &mut hmod as *mut _,
        )
        .is_ok()
            && !hmod.is_invalid()
    }
    // Sometimes, GetModuleHandleEx returns a handle value slightly bigger than the module start
    // address...
    .then_some(HMODULE((hmod.0 as usize & !4095) as *mut _))
}

/// Get information about a module given its handle.
///
/// # Panics
/// If the handle is invalid or does not have enough permissions
pub fn module_info(hmod: HMODULE) -> MODULEINFO {
    let mut minfo = MODULEINFO::default();
    unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            hmod,
            &mut minfo as *mut _,
            std::mem::size_of_val(&minfo) as u32,
        )
        .inspect_err(|e| panic!("GetModuleInformation failed: {e:?}"))
        .ok();
    };

    minfo
}

/// Gets the region of memory occupied by a module given its handle
pub fn module_region(hmod: HMODULE) -> Range<usize> {
    let minfo = module_info(hmod);
    let start = minfo.lpBaseOfDll as usize;
    let end = unsafe { minfo.lpBaseOfDll.byte_add(minfo.SizeOfImage as usize) } as usize;
    start..end
}
