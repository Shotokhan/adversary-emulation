#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct FsFuncs {
    pub zw_create_file: ntdef::functions::ZwCreateFile,
    pub zw_query_directory_file: ntdef::functions::ZwQueryDirectoryFile,
    pub zw_close: ntdef::functions::ZwClose,
    pub ex_allocate_pool: ntdef::functions::ExAllocatePool,
    pub ex_free_pool_with_tag: ntdef::functions::ExFreePoolWithTag,
    pub zw_write_file: ntdef::functions::ZwWriteFile,
    pub zw_read_file: ntdef::functions::ZwReadFile,
}

pub unsafe fn open_file(funcs: *const FsFuncs, filename: *mut u8, handle: ntdef::types::PHANDLE, 
    buf_size: u32, write: u32)
-> u32 {
    let unicode_str: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool as _, filename, buf_size
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

    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let access_mask: u32;
    let create_disposition: u32;
    if write == 1 as _ {
        access_mask = ntdef::enums::GENERIC_WRITE;
        create_disposition = ntdef::enums::FILE_OVERWRITE_IF;
    } else {
        access_mask = ntdef::enums::GENERIC_READ;
        create_disposition = ntdef::enums::FILE_OPEN;
    }

    let status = ((*funcs).zw_create_file)(
        handle as _,
        access_mask,
        obj_attrs as _,
        io_status_block as _,
        core::ptr::null_mut(),
        ntdef::enums::FILE_ATTRIBUTE_NORMAL,
        ntdef::enums::FILE_SHARE_READ,
        create_disposition,
        ntdef::enums::FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0
    );

    ((*funcs).ex_free_pool_with_tag)(unicode_str as _, 9);
    ((*funcs).ex_free_pool_with_tag)(obj_attrs as _, 9);
    ((*funcs).ex_free_pool_with_tag)(io_status_block as _, 9);

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;

 }

pub unsafe fn write_file(funcs: *const FsFuncs, handle: ntdef::types::HANDLE, buf: *mut u8, len: u32) 
-> u32 {
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let status = ((*funcs).zw_write_file)(
        handle as _,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        io_status_block as _,
        buf as _,
        len as _,
        core::ptr::null_mut(),
        core::ptr::null_mut()
    );

    ((*funcs).ex_free_pool_with_tag)(io_status_block as _, 10);

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;    
}


pub unsafe fn read_file(funcs: *const FsFuncs, handle: ntdef::types::HANDLE, buf: *mut u8, len: u32) 
-> (u32, u32) {
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let status = ((*funcs).zw_read_file)(
        handle as _,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        io_status_block as _,
        buf as _,
        len as _,
        core::ptr::null_mut(),
        core::ptr::null_mut()
    );

    let mut ret_val: u32 = 0;
    let n_bytes_read: u32 = (*io_status_block).Information as _;

    if !ntdef::macros::NT_SUCCESS(status) {
        ret_val = 1 as _;
    } else if len == n_bytes_read {
        ret_val = 2 as _;   // read was successful, end of file has not been reached
    }

    ((*funcs).ex_free_pool_with_tag)(io_status_block as _, 11);

    return (ret_val, n_bytes_read);    
}


pub unsafe fn open_directory(funcs: *const FsFuncs, dirname: *mut u8, handle: ntdef::types::PHANDLE, buf_size: u32)
-> u32 {
    let unicode_str: ntdef::structs::PUNICODE_STRING = ntdef::macros::BuildUnicodeStringFromCharArray(
        (*funcs).ex_allocate_pool, dirname, buf_size
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
    
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let status = ((*funcs).zw_create_file)(
        handle as _,
        ntdef::enums::FILE_LIST_DIRECTORY | ntdef::enums::FILE_READ_EA | ntdef::enums::FILE_TRAVERSE | ntdef::enums::FILE_READ_ATTRIBUTES | ntdef::enums::SYNCHRONIZE,
        obj_attrs as _,
        io_status_block as _,
        core::ptr::null_mut(),
        ntdef::enums::FILE_ATTRIBUTE_NORMAL,
        ntdef::enums::FILE_SHARE_READ,
        ntdef::enums::FILE_OPEN,
        ntdef::enums::FILE_DIRECTORY_FILE | ntdef::enums::FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0
    );

    ((*funcs).ex_free_pool_with_tag)(unicode_str as _, 7);
    ((*funcs).ex_free_pool_with_tag)(obj_attrs as _, 7);
    ((*funcs).ex_free_pool_with_tag)(io_status_block as _, 7);

    if !ntdef::macros::NT_SUCCESS(status) {
        return 1;
    }

    return 0;
}

pub unsafe fn query_directory(funcs: *const FsFuncs, handle: ntdef::types::HANDLE, buf: *mut u8, len: u32) 
-> ntdef::types::NTSTATUS {
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let file_information_class: ntdef::types::FILE_INFORMATION_CLASS = ntdef::enums::FILE_NAMES_INFORMATION;
    let status: ntdef::types::NTSTATUS = ((*funcs).zw_query_directory_file)(
        handle as _,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        io_status_block as _,
        buf as _,
        len as _,
        file_information_class,
        ntdef::enums::FALSE as _,
        core::ptr::null_mut(),
        ntdef::enums::TRUE as _
    );
    ((*funcs).ex_free_pool_with_tag)(io_status_block as _, 8);
    return status;
}


pub unsafe fn close_handle(funcs: *const FsFuncs, handle: ntdef::types::HANDLE) -> () {
    ((*funcs).zw_close)(handle);
}
