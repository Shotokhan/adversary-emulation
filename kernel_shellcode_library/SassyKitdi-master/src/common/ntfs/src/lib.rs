#![no_std]
#![feature(core_intrinsics)]

#[repr(C, packed)]
pub struct FsFuncs {
    pub zw_create_file: ntdef::functions::ZwCreateFile,
    pub zw_query_directory_file: ntdef::functions::ZwQueryDirectoryFile,
    pub zw_close: ntdef::functions::ZwClose,
    pub ex_allocate_pool: ntdef::functions::ExAllocatePool,
    pub ex_free_pool_with_tag: ntdef::functions::ExFreePoolWithTag
}

pub unsafe fn open_directory(funcs: *const FsFuncs, dirname: *mut u8, handle: ntdef::types::PHANDLE)
-> u32 {
    // this len must result at most 1460 / 2 = 730
    let mut len: isize = ntdef::macros::Strlen(dirname) as _;
    if len > 730 {
        len = 730 as _;
    }
    let mut i: isize = len - 1;
    while i >= 0 {
        *((dirname as *mut u16).offset(i)) = *(dirname.offset(i)) as u16;
        i = i - 1;
    }
    let unicode_str: ntdef::structs::PUNICODE_STRING = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;
    (*unicode_str).Length = (len*2) as u16;
    (*unicode_str).MaximumLength = 1460 as u16;
    (*unicode_str).Buffer = dirname as *mut u16;
    /*
    let mut unicode_str = ntdef::structs::UNICODE_STRING {
        Length: (len*2) as u16,
        MaximumLength: 1460 as u16,
        Buffer: dirname as *mut u16
    };
    */

    // let mut obj_attrs: ntdef::structs::OBJECT_ATTRIBUTES = core::mem::MaybeUninit::uninit().assume_init();
    let obj_attrs: ntdef::structs::POBJECT_ATTRIBUTES = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 64
    ) as _;
    ntdef::macros::InitializeObjectAttributes(
        // &mut obj_attrs as _,
        obj_attrs as _,
        // &mut unicode_str as _,
        unicode_str as _,
        ntdef::enums::OBJ_CASE_INSENSITIVE | ntdef::enums::OBJ_KERNEL_HANDLE,
        core::ptr::null_mut(),
        core::ptr::null_mut()
    );
    
    // let mut io_status_block: ntdef::structs::IO_STATUS_BLOCK = core::mem::MaybeUninit::uninit().assume_init();
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let mut status = ((*funcs).zw_create_file)(
        handle as _,
        ntdef::enums::FILE_LIST_DIRECTORY | ntdef::enums::FILE_READ_EA | ntdef::enums::FILE_TRAVERSE | ntdef::enums::FILE_READ_ATTRIBUTES | ntdef::enums::SYNCHRONIZE,
        // &mut obj_attrs as _,
        obj_attrs as _,
        // &mut io_status_block as _,
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

pub unsafe fn query_directory(funcs: *const FsFuncs, handle: ntdef::types::HANDLE, buf: *mut u8) 
-> ntdef::types::NTSTATUS {
    // assuming supplied buf has a length of 1460
    // let mut io_status_block: ntdef::structs::IO_STATUS_BLOCK = core::mem::MaybeUninit::uninit().assume_init();
    let io_status_block: ntdef::structs::PIO_STATUS_BLOCK = ((*funcs).ex_allocate_pool)(
        ntdef::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;

    let file_information_class: ntdef::types::FILE_INFORMATION_CLASS = ntdef::enums::FILE_NAMES_INFORMATION;
    let status: ntdef::types::NTSTATUS = ((*funcs).zw_query_directory_file)(
        handle as _,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        // &mut io_status_block as _,
        io_status_block as _,
        buf as _,
        1460, // can hold up to 1460 / 6 filenames => 243 files if all have name length <= 8
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
