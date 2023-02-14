use core::arch::asm;

#[inline]
pub fn NT_SUCCESS(status: i32) -> bool {
    status >= 0
}

pub unsafe fn RtlZeroMemory(
    buffer: *mut u8,
    buffer_size: usize,
) {
    for i in 0..buffer_size {
        *buffer.offset(i as _) = 0;
    }
}

pub unsafe fn RtlCopyMemory(dst: *mut u8, src: *const u8, len: isize) {
	/*
    for i in 0isize..len {
        *dst.offset(i) = *src.offset(i);
    }
    */
    let mut i: isize;
    let mut tmp: u8;
    asm!(
    	"xor {3}, {3}",
    	"5:",
    	"cmp {2}, {3}",
    	"je 6f",
    	"mov {4}, BYTE PTR[{1}+{3}]",
    	"mov BYTE PTR[{0}+{3}], {4}",
    	"inc {3}",
    	"jmp 5b",
    	"6:",
    	in(reg) dst,
    	in(reg) src,
    	in(reg) len,
        out(reg) i,
        out(reg_byte) tmp
    )
}

pub unsafe fn RtlEqualMemory(dst: *mut u8, src: *const u8, len: isize) -> u32 {
    let mut i: isize = 0;
    let mut tmp: u8 = 0;
    let mut result: u32 = 1 as _;
    asm!(
        "xor {3}, {3}",
        "7:",
        "cmp {2}, {3}",
        "je 9f",
        "mov {4}, BYTE PTR[{0}+{3}]",
        "cmp {4}, BYTE PTR[{1}+{3}]",
        "je 8f",
        "xor {5:e}, {5:e}",
        "jmp 9f",
        "8:",
        "inc {3}",
        "jmp 7b",
        "9:",
        in(reg) dst,
        in(reg) src,
        in(reg) len,
        out(reg) i,
        out(reg_byte) tmp,
        inout(reg) result
    );
    result
}

pub unsafe fn Strlen(src: *const u8) -> isize {
    let mut i: isize;
    asm!(
        "xor {1}, {1}",
        "3:",
        "cmp BYTE PTR[{0}+{1}], 0",
        "je 4f",
        "inc {1}",
        "jmp 3b",
        "4:",
        in(reg) src,
        out(reg) i
    );
    return i;
}

pub unsafe fn IntFromStr(src: *const u8) -> u64 {
    let mut result: u64 = 0;
    let len: isize = crate::macros::Strlen(src);
    let mut current_val: u8;
    for i in 0..len {
        current_val = *(src.offset(i)) - 0x30;
        result = result * 10;
        result = result + current_val as u64;
    }
    return result;
}

#[cfg(target_arch ="x86_64")]
pub unsafe fn IoGetNextIrpStackLocation(
    irp:       crate::structs::PIRP
) -> crate::structs::PIO_STACK_LOCATION {
    let irp = irp as *mut u8;

    // return ((Irp)->Tail.Overlay.CurrentStackLocation - 1 );
    let current_stack = *(irp.offset(0xb8) as *mut usize);              // mov     rax, [rax+0B8h]
    let next_stack = current_stack as usize - 0x48usize;     // sub     rax, 48h

    next_stack as _
}

pub unsafe fn IoSetCompletionRoutine(
    pirp:                   crate::structs::PIRP,
    completion_routine:     crate::types::PVOID,
    context:                crate::types::PVOID,
    invoke_on_success:      crate::types::BOOLEAN,
    invoke_on_error:        crate::types::BOOLEAN,
    invoke_on_cancel:       crate::types::BOOLEAN,
) -> () {
    let irp_sp = IoGetNextIrpStackLocation(pirp);

    (*irp_sp).CompletionRoutine = completion_routine;
    (*irp_sp).Context = context;
    (*irp_sp).Control = 0;
    
    if invoke_on_success != crate::enums::FALSE as _ {
        (*irp_sp).Control = crate::enums::SL_INVOKE_ON_SUCCESS;
    }

    if invoke_on_error != crate::enums::FALSE as _ {
        (*irp_sp).Control |= crate::enums::SL_INVOKE_ON_ERROR;
    }

    if invoke_on_cancel != crate::enums::FALSE as _ {
        (*irp_sp).Control |= crate::enums::SL_INVOKE_ON_CANCEL;
    }
}

#[inline]
pub unsafe fn InitializeObjectAttributes(
    p: crate::structs::POBJECT_ATTRIBUTES,
    n: crate::structs::PUNICODE_STRING,
    a: crate::types::ULONG,
    r: crate::types::HANDLE,
    s: crate::types::PVOID
) {
    (*p).Length = core::mem::size_of::<crate::structs::OBJECT_ATTRIBUTES>() as _;
    (*p).RootDirectory = r;
    (*p).Attributes = a;
    (*p).ObjectName = n;
    (*p).SecurityDescriptor = s;
    (*p).SecurityQualityOfService = core::ptr::null_mut();
}

#[inline]
pub unsafe fn BuildUnicodeStringFromCharArray(
    ex_allocate_pool: crate::functions::ExAllocatePool,
    char_array:       *mut u8,
    array_size:       u32
) -> crate::structs::PUNICODE_STRING {
    let mut len: isize = crate::macros::Strlen(char_array) as _;
    if (len<<1) > array_size as _ {
        len = (array_size>>1) as _;
    }
    let mut i: isize = len - 1;
    while i >= 0 {
        *((char_array as *mut u16).offset(i)) = *(char_array.offset(i)) as u16;
        i = i - 1;
    }
    let unicode_str: crate::structs::PUNICODE_STRING = (ex_allocate_pool)(
        crate::enums::POOL_TYPE::NonPagedPool, 16
    ) as _;
    (*unicode_str).Length = (len<<1) as u16;
    (*unicode_str).MaximumLength = array_size as u16;
    (*unicode_str).Buffer = char_array as *mut u16;
    return unicode_str;
}

#[inline]
pub unsafe fn TdiBuildInternalDeviceControlIrp(
    io_build_device_io_control_request: crate::functions::IoBuildDeviceIoControlRequest,
    _IrpSubFunction:    crate::types::CCHAR,
    DeviceObject:       crate::structs::PDEVICE_OBJECT,
    _FileObject:        crate::structs::PFILE_OBJECT,
    Event:              crate::structs::PKEVENT,
    IoStatusBlock:      crate::structs::PIO_STATUS_BLOCK
) -> crate::structs::PIRP {

    io_build_device_io_control_request(
        0x00000003,
        DeviceObject,
        crate::enums::NULL,
        0,
        crate::enums::NULL,
        0,
        crate::enums::TRUE as _,
        Event,
        IoStatusBlock,
    )
}

unsafe fn TdiBuildCommonInternal(
    Irp:                crate::structs::PIRP,
    DeviceObject:       crate::structs::PDEVICE_OBJECT,
    FileObject:         crate::structs::PFILE_OBJECT,
    CompletionRoutine:  crate::types::PVOID,
    Context:            crate::types::PVOID,
    MinorFunction:      u8
) -> crate::structs::PIO_STACK_LOCATION {
    if CompletionRoutine != crate::enums::NULL {
        IoSetCompletionRoutine(
            Irp, 
            CompletionRoutine, 
            Context, 
            crate::enums::TRUE as _, 
            crate::enums::TRUE as _, 
            crate::enums::TRUE as _
        );
    }
    else {
        IoSetCompletionRoutine(
            Irp, 
            crate::enums::NULL as _,
            crate::enums::NULL as _, 
            crate::enums::FALSE as _, 
            crate::enums::FALSE as _, 
            crate::enums::FALSE as _
        );
    }

    let irpsp = crate::macros::IoGetNextIrpStackLocation(Irp);
    (*irpsp).MajorFunction = crate::enums::IRP_MJ_INTERNAL_DEVICE_CONTROL;
    (*irpsp).MinorFunction = MinorFunction; 
    (*irpsp).DeviceObject = DeviceObject;
    (*irpsp).FileObject = FileObject;

    irpsp
}

#[inline]
pub unsafe fn TdiBuildAssociateAddress(
    Irp:                crate::structs::PIRP,
    DeviceObject:       crate::structs::PDEVICE_OBJECT,
    FileObject:         crate::structs::PFILE_OBJECT,
    CompletionRoutine:  crate::types::PVOID,
    Context:            crate::types::PVOID,
    AddressHandle:      crate::types::HANDLE,
) {
    let irpsp = TdiBuildCommonInternal(
        Irp,
        DeviceObject,
        FileObject,
        CompletionRoutine,
        Context,
        crate::enums::TDI_ASSOCIATE_ADDRESS
    );

    let p: crate::structs::PTDI_REQUEST_KERNEL_ASSOCIATE = core::mem::transmute(&(*irpsp).Parameters);
    (*p).AddressHandle = AddressHandle;
}

#[inline]
pub unsafe fn TdiBuildConnect(
    Irp:                crate::structs::PIRP,
    DeviceObject:       crate::structs::PDEVICE_OBJECT,
    FileObject:         crate::structs::PFILE_OBJECT,
    CompletionRoutine:  crate::types::PVOID,
    Context:            crate::types::PVOID,
    Time:               crate::structs::PLARGE_INTEGER,
    RequestConnectionInfo:  crate::structs::PTDI_CONNECTION_INFORMATION,
    ReturnConnectionInfo:   crate::structs::PTDI_CONNECTION_INFORMATION,
) {
    let irpsp = TdiBuildCommonInternal(
        Irp,
        DeviceObject,
        FileObject,
        CompletionRoutine,
        Context,
        crate::enums::TDI_CONNECT
    );


    let p: crate::structs::PTDI_REQUEST_KERNEL = core::mem::transmute(&(*irpsp).Parameters);
    (*p).RequestConnectionInformation = RequestConnectionInfo;
    (*p).ReturnConnectionInformation = ReturnConnectionInfo;
    (*p).RequestSpecific = Time as _;
}

#[inline]
pub unsafe fn TdiBuildSetEventHandler(
    Irp:                crate::structs::PIRP,
    DeviceObject:       crate::structs::PDEVICE_OBJECT,
    FileObject:         crate::structs::PFILE_OBJECT,
    CompletionRoutine:  crate::types::PVOID,
    Context:            crate::types::PVOID,
    InEventType:        crate::types::LONG,
    InEventHandler:     crate::types::PVOID,
    InEventContext:     crate::types::PVOID,
) {
    let irpsp = TdiBuildCommonInternal(
        Irp,
        DeviceObject,
        FileObject,
        CompletionRoutine,
        Context,
        crate::enums::TDI_SET_EVENT_HANDLER
    );

    let p: crate::structs::PTDI_REQUEST_KERNEL_SET_EVENT = core::mem::transmute(&(*irpsp).Parameters);
    (*p).EventType = InEventType;
    (*p).EventHandler = InEventHandler;
    (*p).EventContext = InEventContext;
}

pub unsafe fn make_single_fea(
    fea_buffer:         *mut u8,
    fea_buffer_size:    usize,
    fea_name:           *const u8,
    fea_name_len:       u8,
    fea_value:          *const u8,
    fea_value_len:      u16,
) {
    let fea: crate::structs::PFILE_FULL_EA_INFORMATION = fea_buffer as _;

    // zero the FEA buffer
    crate::macros::RtlZeroMemory(fea_buffer, fea_buffer_size);

    //(*fea).NextEntryOffset = 0;
    //(*fea).Flags = 0;
    (*fea).EaNameLength = fea_name_len;
    (*fea).EaValueLength = fea_value_len;

    let name_start: isize = 8;
    let value_start: isize = name_start + fea_name_len as isize + 1;

    crate::macros::RtlCopyMemory(fea_buffer.offset(name_start), fea_name, fea_name_len as _);

    if fea_value != 0 as *const _ {
        crate::macros::RtlCopyMemory(fea_buffer.offset(value_start), fea_value, fea_value_len as _); 
    }
}
