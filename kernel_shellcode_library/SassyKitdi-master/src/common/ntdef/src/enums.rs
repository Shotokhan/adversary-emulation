pub const TRUE: u32 = 1;
pub const FALSE: u32 = 0;

pub const NULL: crate::types::PVOID = core::ptr::null_mut();

pub const KEY_QUERY_VALUE: u32 =            0x0001;
pub const KEY_SET_VALUE: u32 =              0x0002;
pub const KEY_CREATE_SUB_KEY: u32 =         0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 =     0x0008;
pub const KEY_NOTIFY: u32 =                 0x0010;
pub const KEY_CREATE_LINK: u32 =            0x0020;
pub const KEY_WOW64_32KEY: u32 =            0x0200;
pub const KEY_WOW64_64KEY: u32 =            0x0100;
pub const KEY_WOW64_RES: u32 =              0x0300;

pub const THREAD_ALL_ACCESS: u32 = 0x001FFFFF;

pub const MmNonCached: u32 = crate::enums::FALSE;
pub const MmCached: u32 = crate::enums::TRUE;

pub const FILE_DIRECTORY_FILE: u32 = 0x1;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;

pub const FILE_NAMES_INFORMATION: u32 = 0xc;

pub const FILE_LIST_DIRECTORY: u32 = 0x1;
pub const FILE_OPEN: u32 = 0x1;

pub const FILE_READ_EA: u32 = 0x8;
pub const FILE_WRITE_EA: u32 = 0x10;

pub const FILE_TRAVERSE: u32 = 0x20;
pub const FILE_READ_ATTRIBUTES: u32 = 0x80;

pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

pub const FILE_OPEN_IF: u32 = 0x3;
pub const FILE_OVERWRITE_IF: u32 = 0x5;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;

pub const SYNCHRONIZE: u32 = 0x00100000;

pub const STANDARD_RIGHTS_READ: u32 = 0x00020000;
pub const STANDARD_RIGHTS_WRITE: u32 = 0x00020000;
pub const STANDARD_RIGHTS_ALL: u32 = 0x001F0000;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

pub const KEY_READ: u32 = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY;
pub const KEY_WRITE: u32 = STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
pub const KEY_ALL_ACCESS: u32 = STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK;

pub const FILE_SHARE_READ: u32 = 0x1;

pub const OBJ_INHERIT: u32 = 0x00000002;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;

pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;

#[repr(i32)]
pub enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation            = 0,
    KeyValueFullInformation             = 1,
    KeyValuePartialInformation          = 2,
    KeyValueFullInformationAlign64      = 3,
    KeyValuePartialInformationAlign64   = 4,
    MaxKeyValueInfoClass                = 5,
}

pub const REG_OPTION_NON_VOLATILE: u32 = 0x0 as _;
pub const REG_OPTION_VOLATILE: u32 = 0x1 as _;

pub const REG_NONE: u32 = 0x0;
pub const REG_SZ: u32 = 0x1;
pub const REG_EXPAND_SZ: u32 = 0x2;
pub const REG_BINARY: u32 = 0x3;
pub const REG_DWORD: u32 = 0x4;
pub const REG_DWORD_LITTLE_ENDIAN: u32 = 0x4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 0x5;
pub const REG_LINK: u32 = 0x6;
pub const REG_MULTI_SZ: u32 = 0x7;
pub const REG_RESOURCE_LIST: u32 = 0x8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 0x9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 0x10;
pub const REG_QWORD: u32 = 0x11;
pub const REG_QWORD_LITTLE_ENDIAN: u32 = 0x11;

pub const SECTION_QUERY: u32 = 0x1;
pub const SECTION_MAP_WRITE: u32 = 0x2;
pub const SECTION_MAP_READ: u32 = 0x4;
pub const SECTION_MAP_EXECUTE: u32 = 0x8;
pub const SECTION_EXTEND_SIZE: u32 = 0x10;
pub const SECTION_MAP_EXECUTE_EXPLICIT: u32 = 0x20;
pub const SECTION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;

pub const PS_REQUEST_BREAKAWAY: u32 = 0x1;
pub const PS_NO_DEBUG_INHERIT: u32 = 0x2;
pub const PS_INHERIT_HANDLES: u32 = 0x4;
pub const PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE: u32 = 0x8;
pub const PROCESS_CREATE_FLAGS_LARGE_PAGES: u32 = 0x10;
pub const PS_ALL_FLAGS: u32 = PS_REQUEST_BREAKAWAY | PS_NO_DEBUG_INHERIT | PS_INHERIT_HANDLES | PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE;
pub const PROCESS_CREATE_FLAGS_LEGAL_MASK: u32 = PROCESS_CREATE_FLAGS_LARGE_PAGES | PS_ALL_FLAGS;

pub const SEC_IMAGE: u32 = 0x1000000;

pub const IO_COMPLETION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3;

pub const WORKER_FACTORY_RELEASE_WORKER: u32 = 0x0001;
pub const WORKER_FACTORY_WAIT: u32 = 0x0002;
pub const WORKER_FACTORY_SET_INFORMATION: u32 = 0x0004;
pub const WORKER_FACTORY_QUERY_INFORMATION: u32 = 0x0008;
pub const WORKER_FACTORY_READY_WORKER: u32 = 0x0010;
pub const WORKER_FACTORY_SHUTDOWN: u32 = 0x0020;

pub const WORKER_FACTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | WORKER_FACTORY_RELEASE_WORKER | WORKER_FACTORY_WAIT | WORKER_FACTORY_SET_INFORMATION | WORKER_FACTORY_QUERY_INFORMATION | WORKER_FACTORY_READY_WORKER | WORKER_FACTORY_SHUTDOWN;
pub const WORKER_ACCESS: u32 = 0xF00FF;

#[repr(i32)]
pub enum WORKER_FACTORY_INFORMATION_CLASS {
    WorkerFactoryMinimumThreadInformation = 4,
}

// CPU modes
#[repr(i32)]
pub enum KPROCESSOR_MODE {
    KernelMode = 0,
    UserMode = 1,
}

#[repr(i32)]
pub enum LOCK_OPERATION {
    IoReadAccess = 0,
    IoWriteAccess = 1,
    IoModifyAccess = 2,
}

// Pools
#[repr(i32)]
pub enum POOL_TYPE {
    NonPagedPool = 0,
    PagedPool = 1,
    NonPagedPoolNx = 512,
}

#[repr(i32)]
pub enum EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
}

#[repr(i32)]
pub enum KWAIT_REASON {
    Executive = 0,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    MaximumWaitReason
}

pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;

// TDI
pub const TDI_ASSOCIATE_ADDRESS: u8 = 0x1;
pub const TDI_DISASSOCIATE_ADDRESS: u8 = 0x2;
pub const TDI_CONNECT: u8 = 0x3;
pub const TDI_LISTEN: u8 = 0x4;
pub const TDI_ACCEPT: u8 = 0x5;
pub const TDI_DISCONNECT: u8 = 0x6;
pub const TDI_SEND: u8 = 0x7;
pub const TDI_RECEIVE: u8 = 0x8;
pub const TDI_SEND_DATAGRAM: u8 = 0x9;
pub const TDI_RECEIVE_DATAGRAM: u8 = 0xa;
pub const TDI_SET_EVENT_HANDLER: u8 = 0xb;
pub const TDI_QUERY_INFORMATION: u8 = 0xc;
pub const TDI_SET_INFORMATION: u8 = 0xd;
pub const TDI_ACTION: u8 = 0xe;

pub const TDI_DIRECT_SEND: u8 = 0x27;
pub const TDI_DIRECT_SEND_DATAGRAM: u8 = 0x29;
pub const TDI_DIRECT_ACCEPT: u8 = 0x2a;

pub const TDI_ADDRESS_TYPE_IP: u16 = 2;

pub const TDI_EVENT_CONNECT: u16 = 0;
pub const TDI_EVENT_DISCONNECT: u16 = 1;
pub const TDI_EVENT_ERROR: u16 = 2;
pub const TDI_EVENT_RECEIVE: u16 = 3;
pub const TDI_EVENT_RECEIVE_DATAGRAM: u16 = 4;
pub const TDI_EVENT_RECEIVE_EXPEDITED: u16 = 5;
pub const TDI_EVENT_SEND_POSSIBLE: u16 = 6;

pub const TDI_DISCONNECT_ABORT: u16 = 0x2;

#[allow(overflowing_literals)]
#[repr(i32)]
pub enum NTSTATUS {
    STATUS_SUCCESS = 0,
    STATUS_PENDING = 0x00000103,

    STATUS_NO_MORE_ENTRIES = 0x8000001A,

    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
    STATUS_NOT_FOUND = 0xC0000225,

    STATUS_NOT_LOCKED = 0xC000002A,
}

#[repr(i32)]
pub enum MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
}

#[repr(i32)]
pub enum PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29,
    ProcessSubsystemInformation = 75,
}

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

pub const MEM_COMMIT: u32 = 0x00001000;