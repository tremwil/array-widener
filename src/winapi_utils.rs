use std::{ffi::c_void, ops::Range, sync::LazyLock};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{HANDLE, HMODULE, NTSTATUS},
        System::{
            Diagnostics::Debug::FlushInstructionCache,
            LibraryLoader::{
                GetModuleHandleA, GetModuleHandleExA, GetProcAddress,
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            Threading::{
                GetCurrentProcess, GetCurrentThreadId, GetThreadId, SuspendThread,
                THREAD_ACCESS_RIGHTS, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
            },
        },
    },
};

/// Get an HMODULE given a pointer to memory inside of it.
pub(crate) fn hmodule_from_ptr(ptr: *const ()) -> Option<HMODULE> {
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
pub(crate) fn module_info(hmod: HMODULE) -> MODULEINFO {
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
pub(crate) fn module_region(hmod: HMODULE) -> Range<usize> {
    let minfo = module_info(hmod);
    let start = minfo.lpBaseOfDll as usize;
    let end = unsafe { minfo.lpBaseOfDll.byte_add(minfo.SizeOfImage as usize) } as usize;
    start..end
}

/// Suspends all threads.
///
/// This is only intended to be used when debugging in order to completely pause the process.
pub(crate) fn suspend_threads() {
    type NtGetNextThreadFn = unsafe extern "system" fn(
        proc: HANDLE,
        thread: HANDLE,
        access: THREAD_ACCESS_RIGHTS,
        attr: u32,
        flags: u32,
        new_handle: &mut HANDLE,
    ) -> NTSTATUS;

    static NT_GET_NEXT_HREAD: LazyLock<NtGetNextThreadFn> = LazyLock::new(|| unsafe {
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0" as *const u8)).unwrap();
        std::mem::transmute(
            GetProcAddress(ntdll, PCSTR(b"NtGetNextThread\0" as *const u8)).unwrap(),
        )
    });

    let access = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME;
    unsafe {
        let proc = GetCurrentProcess();
        let this_thread = GetCurrentThreadId();

        let mut thread = HANDLE(std::ptr::null_mut());
        while NT_GET_NEXT_HREAD(proc, thread, access, 0, 0, &mut thread).is_ok() {
            if GetThreadId(thread) != this_thread {
                SuspendThread(thread);
            }
        }
    }
}

pub(crate) unsafe fn patch_code(ip: u64, new_code: &[u8]) {
    let protect_start = (ip & !0xFFF) as *const c_void;
    let protect_size = ip as usize + new_code.len() - protect_start as usize;
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            protect_start,
            protect_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .unwrap();
        std::ptr::copy_nonoverlapping(new_code.as_ptr(), ip as *mut u8, new_code.len());
        VirtualProtect(protect_start, protect_size, old_protect, &mut old_protect).unwrap();

        FlushInstructionCache(GetCurrentProcess(), Some(protect_start), protect_size).ok();
    }
}
