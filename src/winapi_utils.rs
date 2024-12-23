use std::{ops::Range, sync::LazyLock};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{HANDLE, HMODULE, NTSTATUS},
        System::{
            LibraryLoader::{
                GetModuleHandleA, GetModuleHandleExA, GetProcAddress,
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            Threading::{
                GetCurrentProcess, GetCurrentThreadId, GetThreadId, SuspendThread,
                THREAD_ACCESS_RIGHTS, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
            },
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
