use std::error::Error;
mod pmi;

use array_widener::array_widener::{ArrayWidener, ArrayWidenerManager};
use pmi::PartyMemberInfo;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HINSTANCE,
        System::{
            Console::{AllocConsole, GetConsoleWindow},
            LibraryLoader::{DisableThreadLibraryCalls, GetModuleHandleA},
            SystemServices::DLL_PROCESS_ATTACH,
        },
    },
};

fn setup_console() -> Result<(), Box<dyn Error>> {
    unsafe {
        if GetConsoleWindow().0 == std::ptr::null_mut() && AllocConsole().is_err() {
            return Err("Failed to allocate console".into());
        }
        Ok(())
    }
}

fn bootstrap() -> Result<(), Box<dyn Error>> {
    setup_console()?;

    simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Debug).init()?;

    std::io::stdin().read_line(&mut String::new()).unwrap();

    const ALLOC_RVA: u64 = 0x0676681;
    const FREE_RVA: u64 = 0x0677c1f;

    let er_base = unsafe { GetModuleHandleA(PCSTR(std::ptr::null())) }.unwrap().0 as u64;
    log::info!("ER base: {er_base:016x}");

    let pmi_widener = ArrayWidener::new::<PartyMemberInfo<6>, PartyMemberInfo<6>>()
        .alloc_calls([er_base + ALLOC_RVA])
        .free_calls([er_base + FREE_RVA])
        .reserved_memory_size(0x10000)
        .build();

    // Allocate 1MB of hook memory per module
    let mut iaw = ArrayWidenerManager::new(1 << 20);
    iaw.register(pmi_widener);

    unsafe {
        iaw.enable();
    }

    Ok(())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const (),
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(h_inst_dll).ok();

        let _ = std::thread::spawn(move || {
            match std::panic::catch_unwind(bootstrap) {
                Err(e) => {
                    println!("panicked in bootstrap: {:#?}", e)
                }
                Ok(Err(e)) => {
                    println!("error during bootstrap: {:#?}", e)
                }
                _ => (),
            };
        });
    }
    1
}
