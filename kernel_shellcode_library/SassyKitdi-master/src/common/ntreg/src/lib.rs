#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct RegFuncs {
    pub zw_close: ntdef::functions::ZwClose,
    pub ex_allocate_pool: ntdef::functions::ExAllocatePool,
    pub ex_free_pool_with_tag: ntdef::functions::ExFreePoolWithTag,
    pub zw_open_key: ntdef::functions::ZwOpenKey,
    pub zw_query_value_key: ntdef::functions::ZwQueryValueKey,
    pub zw_create_key: ntdef::functions::ZwCreateKey,
    pub zw_set_value_key: ntdef::functions::ZwSetValueKey,
}

pub unsafe fn query_value_key(funcs: *const RegFuncs, handle: ntdef::types::HANDLE,
    value_name: ntdef::structs::PUNICODE_STRING, buf: *mut u8, buf_size: u32)
-> (u32, u32) {
    let res_len_ptr: ntdef::types::PULONG = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 8
    ) as _;
    let mut ret_val: u32;
    let mut res_len: u32;

    let status = ((*funcs).zw_query_value_key)(
        handle as _,
        value_name as _,
        ntdef::enums::_KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation as _,
        buf as _,
        buf_size as _,
        res_len_ptr
    );

    if !ntdef::macros::NT_SUCCESS(status) {
        ret_val = 1 as _;
        res_len = 0 as _;
    } else {
        ret_val = 0 as _;
        res_len = (*res_len_ptr) as _;
    }

    ((*funcs).ex_free_pool_with_tag)(res_len_ptr as _, 21);

    return (ret_val, res_len);
}


pub unsafe fn set_key(funcs: *const RegFuncs, handle: ntdef::types::HANDLE, value_name: *mut u8, 
    value_buf_size: u32, key_type: ntdef::types::ULONG, data: ntdef::types::PVOID, data_size: u32)
-> u32 {
    let unicode_value_name: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool as _, value_name, value_buf_size
    );

    let mut key_val: ntdef::types::PVOID = data as _;

    if key_type == ntdef::enums::REG_SZ as _ {
        key_val = ntdef::macros::BuildUnicodeStringFromCharArray(
            (*funcs).ex_allocate_pool as _, data as _, data_size as _
        ) as _;
    }

    let status = ((*funcs).zw_set_value_key)(
        handle as _,
        unicode_value_name as _,
        0 as _,
        key_type as _,
        data as _,      // in case of REG_SZ, still the raw unicode str has to be passed
        data_size as _
    );

    ((*funcs).ex_free_pool_with_tag)(unicode_value_name as _, 38);
    if key_type == ntdef::enums::REG_SZ as _ {
        ((*funcs).ex_free_pool_with_tag)(key_val as _, 380);
    }

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;
}


pub unsafe fn create_key(funcs: *const RegFuncs, key_name: *mut u8, handle: ntdef::types::PHANDLE, 
    key_name_buf_size: u32/*, class: *mut u8, class_buf_size: u32*/)
-> u32 {
    let unicode_key: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool as _, key_name, key_name_buf_size
    );

    let obj_attrs: ntdef::structs::POBJECT_ATTRIBUTES = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 64
    ) as _;
    ntdef::macros::InitializeObjectAttributes(
        obj_attrs as _,
        unicode_key as _,
        ntdef::enums::OBJ_CASE_INSENSITIVE | ntdef::enums::OBJ_KERNEL_HANDLE,
        core::ptr::null_mut(),
        core::ptr::null_mut()
    );

    /*
    let unicode_class: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool as _, class, class_buf_size
    );
    */

    let status = ((*funcs).zw_create_key)(
        handle as _,
        ntdef::enums::KEY_WRITE,
        obj_attrs as _,
        0 as _,
        // unicode_class as _,
        core::ptr::null_mut(),
        ntdef::enums::REG_OPTION_NON_VOLATILE,
        core::ptr::null_mut()
    );

    // ((*funcs).ex_free_pool_with_tag)(unicode_class as _, 37);
    ((*funcs).ex_free_pool_with_tag)(unicode_key as _, 37);
    ((*funcs).ex_free_pool_with_tag)(obj_attrs as _, 37);

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;
}


pub unsafe fn open_key(funcs: *const RegFuncs, key_name: *mut u8, handle: ntdef::types::PHANDLE,
    buf_size: u32, write: u32)
-> u32 {
    let unicode_str: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool as _, key_name, buf_size
    );

    let obj_attrs: ntdef::structs::POBJECT_ATTRIBUTES = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 64
    ) as _;
    ntdef::macros::InitializeObjectAttributes(
        obj_attrs as _,
        unicode_str as _,
        ntdef::enums::OBJ_CASE_INSENSITIVE | ntdef::enums::OBJ_KERNEL_HANDLE,
        core::ptr::null_mut(),
        core::ptr::null_mut()
    );

    let access_mask: u32;
    if write == 1 as _ {
        access_mask = ntdef::enums::KEY_WRITE;
    } else {
        access_mask = ntdef::enums::KEY_READ;
    }

    let status = ((*funcs).zw_open_key)(
        handle as _,
        access_mask as _,
        obj_attrs as _
    );

    ((*funcs).ex_free_pool_with_tag)(unicode_str as _, 20);
    ((*funcs).ex_free_pool_with_tag)(obj_attrs as _, 20);

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;
}

pub unsafe fn close_handle(funcs: *const RegFuncs, handle: ntdef::types::HANDLE) -> () {
    ((*funcs).zw_close)(handle);
}
